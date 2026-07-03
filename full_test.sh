#!/usr/bin/env bash
# Full test sweep for PhishingShield.
# Run from the repo root while `uvicorn main:app --reload` is running in another terminal.
#
# Usage:
#   chmod +x full_test.sh
#   ./full_test.sh

set -uo pipefail
BASE="http://localhost:8000"
PASS=0
FAIL=0

# Pull the real API key out of .env so it's never typed/shown manually.
API_KEY=$(grep "^API_KEY=" .env 2>/dev/null | head -1 | cut -d= -f2)

section() { echo; echo "==================== $1 ===================="; }
check() {
    # check "description" expected_status actual_status
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" == "$actual" ]; then
        echo "PASS  [$actual] $desc"
        PASS=$((PASS+1))
    else
        echo "FAIL  expected $expected got $actual — $desc"
        FAIL=$((FAIL+1))
    fi
}

status_of() {
    # status_of METHOD PATH [extra curl args...]
    local method="$1"; shift
    local path="$1"; shift
    curl -s -o /tmp/full_test_body.json -w "%{http_code}" -X "$method" "$BASE$path" "$@"
}


section "1. Unit test suite"
python -m pytest test_domain_policy.py test_modernization_framework.py \
    test_production_architecture.py test_security_improvements.py -q \
    || echo "(one or more pytest files above failed or was not found — check output)"


section "2. Basic health / status endpoints"
code=$(status_of GET "/"); check "root status" "200" "$code"; cat /tmp/full_test_body.json; echo
code=$(status_of GET "/api/v1/health"); check "v1 health" "200" "$code"
code=$(status_of GET "/api/v1/live"); check "v1 liveness" "200" "$code"
code=$(status_of GET "/api/v1/ready"); check "v1 readiness" "200" "$code"; cat /tmp/full_test_body.json; echo


section "3. Auth enforcement on /check"
code=$(status_of POST "/check" -H "Content-Type: application/json" -d '{"url":"https://google.com"}')
check "no API key -> should be rejected" "401" "$code"

if [ -n "$API_KEY" ]; then
    code=$(status_of POST "/check" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d '{"url":"https://google.com"}')
    check "valid API key -> should succeed" "200" "$code"
else
    echo "SKIP  API_KEY not found in .env — skipping authenticated tests"
fi


section "4. Auth enforcement on /logs"
code=$(status_of GET "/logs")
check "no API key -> /logs should be rejected" "401" "$code"


section "5. URL category tests (all authenticated)"
declare -A urls=(
    ["trusted domain (google.com)"]="https://google.com"
    ["trusted domain (paypal.com)"]="https://paypal.com"
    ["obvious phishing-style URL"]="http://xoauth-paypa1-secure-login.tk/verify"
    ["private IP - loopback"]="http://127.0.0.1/admin"
    ["private IP - RFC1918"]="http://192.168.1.5/x"
    ["cloud metadata endpoint"]="http://169.254.169.254/latest/meta-data/"
    ["IPv6 loopback"]="http://[::1]/"
    ["localhost hostname"]="http://localhost/"
    ["homoglyph-style domain"]="https://paypa1.com"
    ["long random subdomain"]="https://aksjdhaksjdhakjshdkajshdkajshdaksjdh.example.com"
    ["punycode-looking domain"]="http://xn--pypal-4ve.com"
    ["no scheme provided"]="google.com"
)

for desc in "${!urls[@]}"; do
    url="${urls[$desc]}"
    if [ -n "$API_KEY" ]; then
        response=$(curl -s -X POST "$BASE/check" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d "{\"url\":\"$url\"}")
    else
        response=$(curl -s -X POST "$BASE/check" -H "Content-Type: application/json" -d "{\"url\":\"$url\"}")
    fi
    echo "---- $desc ----"
    echo "  url: $url"
    echo "  response: $response"
done


section "6. Malformed / edge-case input"
code=$(status_of POST "/check" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d '{}')
check "missing url field -> validation error" "422" "$code"

code=$(status_of POST "/check" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d '{"url":""}')
echo "  empty url string -> status $code (inspect body: $(cat /tmp/full_test_body.json))"

code=$(status_of POST "/check" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d '{"url":"not a url at all!!!"}')
echo "  garbage input -> status $code (inspect body: $(cat /tmp/full_test_body.json))"


section "7. New modular pipeline (/api/v1/analyze)"
code=$(status_of POST "/api/v1/analyze" -H "Content-Type: application/json" -d '{"url":"https://google.com"}')
check "v1 analyze trusted domain" "200" "$code"
cat /tmp/full_test_body.json; echo

code=$(status_of POST "/api/v1/analyze" -H "Content-Type: application/json" -d '{"url":"http://xoauth-paypa1-secure-login.tk/verify"}')
check "v1 analyze phishing-style URL" "200" "$code"
cat /tmp/full_test_body.json; echo

code=$(status_of POST "/api/v1/analyze" -H "Content-Type: application/json" -d '{"url":"http://169.254.169.254/latest/meta-data/"}')
check "v1 analyze SSRF target" "200" "$code"
cat /tmp/full_test_body.json; echo


section "8. Rate limiting (rapid-fire requests)"
echo "Firing 35 rapid requests to /check (limiter default is 60/hour, 200/day - adjust expectation if you changed limits)..."
rate_limited=0
for i in $(seq 1 35); do
    code=$(status_of POST "/check" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d '{"url":"https://example.com"}')
    if [ "$code" == "429" ]; then
        rate_limited=$((rate_limited+1))
    fi
done
echo "  $rate_limited / 35 requests were rate-limited (429). If 0, rate limiting may not be wired into main.py's /check route yet."


section "SUMMARY"
echo "Automated pass/fail checks: $PASS passed, $FAIL failed."
echo "Review the URL category and edge-case sections above manually — those print raw responses for you to eyeball, since 'correct' scores are judgment calls, not simple pass/fail."
