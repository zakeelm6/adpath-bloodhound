# adpath : offline BloodHound triage + interactive kill chain

Outil générique (**un seul fichier Python, zéro dépendance**) qui lit un export **SharpHound / bloodhound-python** et en sort, en quelques secondes : les **quick-wins** d'identifiants, les **cibles à privilèges**, et le(s) **chemin(s) d'attaque**, avec un **rapport HTML interactif** (schéma cliquable, fiches par profil, et un playbook Kill Chain dont les commandes se remplissent avec ton contexte).

Pensé pour aller vite en début d'engagement / CTF, avant (ou sans) lancer la stack BloodHound.

> ⚠️ **Usage autorisé uniquement** : lab, CTF, ou test d'intrusion avec mandat écrit. L'auteur décline toute responsabilité en cas d'usage illégal.

## adpath vs BloodHound CE : pourquoi les deux

BloodHound CE (web-app Docker : neo4j + UI, dépôt du zip, graphe, requêtes Cypher) reste la référence pour l'analyse de graphe (pathfinding libre, RBCD, ADCS ESC, sessions, cross-domain). adpath ne le remplace pas. Il le complète là où BloodHound ne va pas :

- **Triage instantané, zéro install, offline** : `adpath dump.zip` donne un rapport en 2 s, sans stack Docker.
- **Playbook Kill Chain interactif** : commandes d'attaque pré-remplies de ton contexte (DC, user, pass, hash), ce que BloodHound ne fait pas.
- **Artefact autonome** (un seul fichier HTML) à joindre à un rapport.

Pour l'analyse de graphe poussée : BloodHound CE. Pour un coup d'œil rapide plus les commandes prêtes : adpath.

## Installation

Pas de dépendance obligatoire (Python 3 standard). Trois façons de l'utiliser :

```bash
# 1. Direct, sans rien installer
python3 adpath.py <dossier|zip> [options]

# 2. Comme commande, via pipx (recommandé), directement depuis le repo
pipx install git+https://github.com/zakeelm6/adpath-bloodhound
adpath <dossier|zip> [options]

# 3. Avec pip, dans un venv
pip install git+https://github.com/zakeelm6/adpath-bloodhound
```

Le mode `--collect` (optionnel) requiert `bloodhound-python` : `pipx install git+https://github.com/zakeelm6/adpath-bloodhound[collect]` ou `pip install bloodhound`.

## Usage

```bash
# dossier de .json OU directement le .zip exporté
python3 adpath.py <dossier|zip> [options]

# avec des comptes déjà compromis, calcule le plus court chemin vers une cible
python3 adpath.py ./bh_output --owned user1,user2

# rapport HTML interactif, ouvert dans le navigateur
python3 adpath.py export.zip --owned jdoe --html report.html --open

# tout-en-un : collecte BloodHound puis analyse (une seule commande)
python3 adpath.py --collect -d corp.local -u jdoe -p 'Passw0rd!' --dc-ip 10.10.10.10 --html report.html --open
```

### Turnkey : `adpath-auto.sh` (sans sudo)

Collecte, analyse, puis **rapport HTML ouvert automatiquement**. Aucune modif système.

```bash
./adpath-auto.sh <domaine> <user> <password> <dc-ip>
# ex :
./adpath-auto.sh corp.local jdoe 'Passw0rd!' 10.10.10.10
```

Sort tout dans `./adpath_<timestamp>/` : `report.html`, `path.md`, `results.json`.

| Option | Rôle |
|--------|------|
| `input` | dossier de `*_users.json`, ou un `.zip` BloodHound (auto-extrait) |
| `--owned` | comptes compromis (virgules), calcule le chemin depuis eux |
| `--html F` | **rapport HTML interactif** (4 onglets : Résumé, Schéma cliquable, Profils, Kill Chain) |
| `--open` | ouvre le rapport dans le navigateur |
| `--mermaid F` | schéma Mermaid en `.md` |
| `--json F` | résultats en JSON (pour un rapport) |
| `--max-hops N` | profondeur max pour la surface d'attaque (défaut 4) |
| `--collect` | lance `bloodhound-python` puis analyse (avec `-d -u -p --dc-ip`) |

## Ce qu'il détecte

- **Quick-wins** : AS-REP roastable (`dontreqpreauth`), Kerberoastable (`hasspn`), `pwd-not-required`, mots de passe en description, présence LAPS.
- **Cibles à privilèges** par RID bien connus (512 Domain Admins, 519 Enterprise Admins, 544 Administrators, 548 Account Operators, 551 Backup Operators, 526/527 Key Admins…), plus la propriété `highvalue` et `DnsAdmins`. Indépendant de la langue et du domaine.
- **DCSync** : tout principal avec `GetChanges`/`GetChangesAll` sur le domaine.
- **Chemins** : BFS sur **MemberOf** plus **abus d'ACL** (GenericAll, WriteDacl, WriteOwner, Owns, GenericWrite, ForceChangePassword, AllExtendedRights, AddKeyCredentialLink, AddMember/AddSelf, ReadLAPS/AllowedToAct).

## Le rapport HTML (4 onglets)

- **Résumé** : verdict, chemin d'attaque (étapes plus hint d'abus), quick-wins avec commandes copiables, cibles à privilèges.
- **Schéma** : graphe Mermaid **cliquable** (clique un nœud pour ouvrir son profil), avec fallback hors-ligne.
- **Profils** : recherche plus clic sur n'importe quel user/groupe/machine pour voir ses infos (propriétés, groupes, **qui le contrôle**, **ce qu'il contrôle**), navigables entre eux.
- **Kill Chain** : méthodo d'attaque AD en **16 phases** (recon, énum, AS-REP, spray, BloodHound, coercion/relay, Kerberoast, ACL, shadow creds, délégations, ADCS, LAPS/gMSA, DnsAdmins, DCSync, exec, persistance), une sous-page par phase, plusieurs outils et variantes selon la situation, et une **barre de contexte** qui remplit toutes les commandes (DC, user, pass, hash, cible, IP).

Toutes les données sont embarquées dans le HTML, donc ça marche offline (seul le dessin du graphe tire mermaid.js d'un CDN ; le reste fonctionne sans réseau).

## Limites (honnêtes)

- Entrée : JSON **SharpHound / bloodhound-python** (BloodHound 4.x legacy plus format d'import CE). Pas l'API native de BloodHound CE.
- Abus non modélisés dans les chemins : RBCD complet, contraintes de délégation, ADCS (ESCx), sessions/admin-local. Pour ça, BloodHound plus Certipy restent nécessaires. adpath est un **triage rapide**, pas un remplaçant.
- Les arêtes de prise de contrôle sont supposées exploitables sans vérifier les protections (AdminSDHolder, Protected Users…), à valider manuellement.

## Roadmap

- Support delegation/ADCS dans les chemins, sortie Graphviz `.dot`, filtre `--to <cible>`, détection des sessions, mermaid.js embarqué (offline total).

## Licence

MIT, voir [LICENSE](LICENSE).
