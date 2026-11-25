#!/usr/bin/env bash
# Black-box checks against a running VulnTrack: probes, authentication, scoring and the status workflow.
set -euo pipefail

BASE="${1:?usage: smoke-test.sh BASE_URL}"
: "${VULNTRACK_TOKEN:?VULNTRACK_TOKEN must hold the API token}"
AUTH="Authorization: Bearer $VULNTRACK_TOKEN"
JSON="Content-Type: application/json"

fail() { echo "FAIL: $*" >&2; exit 1; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

[[ $(status "$BASE/health") == 200 ]] || fail "/health is not 200"
[[ $(status "$BASE/ready") == 200 ]] || fail "/ready is not 200"
[[ $(status "$BASE/api/findings") == 401 ]] || fail "the API answered without a token"
wrong_token="$(python3 -c "import secrets; print(secrets.token_hex(16))")"
[[ $(status -H "Authorization: Bearer $wrong_token" "$BASE/api/findings") == 401 ]] || fail "the API accepted a wrong token"

created=$(curl -sf -H "$AUTH" -H "$JSON" "$BASE/api/findings" \
  -d '{"title":"Smoke test finding","product":"vulntrack","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}') \
  || fail "could not create a finding"
read -r id score level < <(python3 -c 'import json,sys; f=json.loads(sys.argv[1]); print(f["id"], f["score"], f["severity"])' "$created")
[[ $score == 9.8 && $level == critical ]] || fail "unexpected scoring: $created"

[[ $(status -X PATCH -H "$AUTH" -H "$JSON" -d '{"status":"disclosed"}' "$BASE/api/findings/$id") == 409 ]] \
  || fail "an invalid status transition was accepted"
[[ $(status -X PATCH -H "$AUTH" -H "$JSON" -d '{"status":"triaged"}' "$BASE/api/findings/$id") == 200 ]] \
  || fail "a valid status transition was refused"

echo "smoke test passed (finding $id scored $score, $level)"
