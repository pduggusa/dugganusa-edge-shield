#!/usr/bin/env bash
# DugganUSA Edge Shield — live verification probes.
#
# Config proves what you MEANT to deploy. Only a live probe proves what the edge
# actually does. This runs the probes from CLAUDE.md step 6 and prints PASS/FAIL
# per host. It is a checker, so it exits non-zero when anything FAILs.
#
#   scripts/verify.sh --product www.example.com,api.example.com \
#                     --sensor honeypot.example.com \
#                     [--mode block|observe]
#
# PRODUCT hosts (shielded):
#   block mode:   a scanner UA gets 418 with "X-Powered-By: DugganUSA Edge Shield"
#   observe mode: a scanner UA is let through, response carries
#                 "X-DugganUSA-Observed: scanner"
#   both modes:   a normal browser UA gets 200 (a 3xx redirect also passes)
# SENSOR hosts (never shielded):
#   a scanner UA must show NO shield header at all, whatever the status. Only the
#   Worker's own headers count: a sensor application may answer scanners itself.
#
# Dependencies: bash and curl. Nothing else.

set -u

PRODUCT=""
SENSOR=""
MODE="block"
SCANNER_UA="leakix/1.0"
BROWSER_UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --product) PRODUCT="${2:-}"; shift 2 ;;
    --sensor)  SENSOR="${2:-}"; shift 2 ;;
    --mode)    MODE="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

if [ -z "$PRODUCT" ] && [ -z "$SENSOR" ]; then
  echo "error: give at least one --product or --sensor host" >&2
  usage
fi
if [ "$MODE" != "block" ] && [ "$MODE" != "observe" ]; then
  echo "error: --mode must be block or observe" >&2
  exit 2
fi
command -v curl >/dev/null 2>&1 || { echo "error: curl not found" >&2; exit 2; }

PASSES=0
FAILS=0
HDRS="$(mktemp)"
trap 'rm -f "$HDRS"' EXIT

pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-34s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1));   printf 'FAIL  %-34s %s\n' "$1" "$2"; }

# probe <host> <ua>  → sets CODE, headers in $HDRS
probe() {
  : > "$HDRS"
  CODE="$(curl -sS -o /dev/null -D "$HDRS" -w '%{http_code}' --max-time 20 \
    -A "$2" "https://$1/?edge-shield-verify=$(date +%s)" 2>/dev/null)" || CODE="000"
}

# header <name>  → value of that response header (case-insensitive), or empty
header() {
  grep -i "^$1:" "$HDRS" | head -n 1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}

# Something answered before the Worker could: a WAF rule, Bot Fight Mode or a
# managed challenge. Those run BEFORE Workers, so the shield never saw it.
upstream_hint() {
  if [ "$(header x-blocked-reason)" = "ioc-match" ]; then
    echo " (the shield IOC-blocked YOUR probe IP: it matched the feed, often via a CIDR. Re-run from another network, and look up the range before trusting the block)"
    return
  fi
  if [ -n "$(header cf-mitigated)" ] || { [ "$CODE" = "403" ] && [ -z "$(header x-powered-by)" ]; }; then
    echo " (looks like Cloudflare answered before the Worker: WAF rule, Bot Fight Mode or a challenge)"
  fi
}

split() { echo "$1" | tr ',' ' '; }

for host in $(split "$PRODUCT"); do
  probe "$host" "$SCANNER_UA"
  powered="$(header x-powered-by)"
  observed="$(header x-dugganusa-observed)"
  if [ "$MODE" = "block" ]; then
    if [ "$CODE" = "418" ] && [ "$powered" = "DugganUSA Edge Shield" ]; then
      pass "$host scanner" "418 + X-Powered-By: DugganUSA Edge Shield"
    else
      fail "$host scanner" "got $CODE, X-Powered-By='${powered}', want 418 + shield header$(upstream_hint)"
    fi
  else
    case ",$observed," in
      *,scanner,*) pass "$host scanner (observe)" "$CODE + X-DugganUSA-Observed: $observed" ;;
      *) fail "$host scanner (observe)" "got $CODE, X-DugganUSA-Observed='${observed}', want it to contain 'scanner'$(upstream_hint)" ;;
    esac
  fi

  probe "$host" "$BROWSER_UA"
  case "$CODE" in
    200) pass "$host normal traffic" "200" ;;
    30[1278]) pass "$host normal traffic" "$CODE redirect to $(header location)" ;;
    *) fail "$host normal traffic" "got $CODE, want 200$(upstream_hint)" ;;
  esac
done

for host in $(split "$SENSOR"); do
  probe "$host" "$SCANNER_UA"
  powered="$(header x-powered-by)"
  observed="$(header x-dugganusa-observed)"
  if [ "$CODE" = "000" ]; then
    fail "$host sensor" "no response (DNS, TLS or timeout), cannot prove it is unshielded"
  elif [ "$powered" = "DugganUSA Edge Shield" ] || [ -n "$observed" ]; then
    fail "$host sensor" "SHIELDED: got $CODE with a shield header. Remove the route on this host and add it to SENSOR_HOSTS"
  elif [ "$CODE" = "418" ]; then
    # Only the Worker's own headers count. A sensor app may answer scanners itself.
    pass "$host sensor" "418 from the ORIGIN itself (X-Powered-By: '${powered}'), not from the shield"
  else
    pass "$host sensor" "$CODE, no shield header (raw traffic reaches it)"
  fi
done

echo
echo "$PASSES passed, $FAILS failed"
echo "Next: run 'npx wrangler tail' (add -c <your config>) for a minute while browsing."
echo "      Any 'IOC refresh FAILED' line means IOC blocking is running on an empty or stale cache."
[ "$FAILS" -eq 0 ]
