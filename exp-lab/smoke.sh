#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
yaksha_url="${ARGUS_YAKSHA_URL:-http://127.0.0.1:8790}"
token="ARGUS_CANARY_$(openssl rand -hex 12)"
marker="ARGUS_TELNET_$(openssl rand -hex 10)"

curl --fail --silent --show-error "$yaksha_url/readyz" >/dev/null

shiro_response="$({
  jq -nc \
    --rawfile script "$repo_dir/server/internal/expworkspace/labseeds/shiro-cve-2016-4437.yak" \
    --arg token "$token" \
    '{id:"lab-shiro-smoke",action:"debug",script:$script,params:{target:"http://argus-exp-shiro:8080",canary_token:$token,shiro_key:"kPH+bIxk5D2deZiIxcaaaA=="},timeout_ms:120000,network_targets:["http://argus-exp-shiro:8080","http://argus-exp-canary:8080"],egress:{mode:"direct"}}'
} | curl --fail --silent --show-error -H 'Content-Type: application/json' --data-binary @- "$yaksha_url/v1/execute")"
jq -e '.status == "Succeeded" and .result.vulnerable == true and .result.cve == "CVE-2016-4437" and .evidence.canary_hit == true and (.debug.events | length) >= 4' <<<"$shiro_response" >/dev/null

telnet_response="$({
  jq -nc \
    --rawfile script "$repo_dir/server/internal/expworkspace/labseeds/telnet-unauth-rce.yak" \
    --arg marker "$marker" \
    '{id:"lab-telnet-smoke",action:"debug",script:$script,params:{address:"argus-exp-telnet:23",marker:$marker},timeout_ms:30000,network_targets:["tcp://argus-exp-telnet:23"],egress:{mode:"direct"}}'
} | curl --fail --silent --show-error -H 'Content-Type: application/json' --data-binary @- "$yaksha_url/v1/execute")"
jq -e --arg marker "$marker" '.status == "Succeeded" and .result.vulnerable == true and .evidence.identity_found == true and .evidence.marker_found == true and (.result.output | contains($marker))' <<<"$telnet_response" >/dev/null

wrong_key_response="$({
  jq -nc \
    --rawfile script "$repo_dir/server/internal/expworkspace/labseeds/shiro-cve-2016-4437.yak" \
    --arg token "ARGUS_WRONG_KEY_$(openssl rand -hex 10)" \
    '{id:"lab-shiro-wrong-key",action:"debug",script:$script,params:{target:"http://argus-exp-shiro:8080",canary_token:$token,shiro_key:"MDAwMDAwMDAwMDAwMDAwMA=="},timeout_ms:30000,network_targets:["http://argus-exp-shiro:8080","http://argus-exp-canary:8080"],egress:{mode:"direct"}}'
} | curl --fail --silent --show-error -H 'Content-Type: application/json' --data-binary @- "$yaksha_url/v1/execute")"
jq -e '.status == "Failed" and (.error | contains("default Shiro key validation failed"))' <<<"$wrong_key_response" >/dev/null

printf 'Shiro: %s\n' "$(jq -c '{status,result,evidence,event_count:(.debug.events|length)}' <<<"$shiro_response")"
printf 'Telnet: %s\n' "$(jq -c '{status,result,evidence,event_count:(.debug.events|length)}' <<<"$telnet_response")"
printf 'Negative wrong key: %s\n' "$(jq -c '{status,error}' <<<"$wrong_key_response")"
