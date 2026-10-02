#!/usr/bin/env bash
# adpath-auto — collecte BloodHound + analyse + rapport HTML, en UNE commande. SANS sudo.
#
# Usage :
#   ./adpath-auto.sh <domaine> <user> <password> <dc-ip> [dc-hostname]
# Exemple :
#   ./adpath-auto.sh sevenkingdoms.local isadora.laurena jessie 192.168.122.50 dc01
#
# Note : pas de modif système (ni horloge ni /etc/hosts). La collecte des ACL/users/groups
# passe par LDAP/NTLM via -ns <DC>, non affectée par le clock skew. Lab/engagement autorisé uniquement.
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "Usage: $0 <domaine> <user> <password> <dc-ip> [dc-hostname]" >&2
  exit 1
fi

DOMAIN="$1"; USER="$2"; PASS="$3"; DCIP="$4"; DCHOST="${5:-}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="$(pwd)/adpath_${TS}"
mkdir -p "$OUTDIR"

echo "[*] Collecte BloodHound + analyse + rapport HTML (aucun sudo)…"
python3 "${SCRIPT_DIR}/adpath.py" --collect \
  -d "$DOMAIN" -u "$USER" -p "$PASS" --dc-ip "$DCIP" \
  --out "$OUTDIR" --owned "$USER" \
  --mermaid "${OUTDIR}/path.md" --json "${OUTDIR}/results.json" \
  --html "${OUTDIR}/report.html" --open

echo ""
echo "[+] Terminé. Résultats : $OUTDIR"
echo "    • report.html (ouvert dans le navigateur)"
echo "    • path.md  (Mermaid)   • results.json"
