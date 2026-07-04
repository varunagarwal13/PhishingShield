# PhishingShield Pipeline Regression Verification

## 1. Test Targets Execution Matrix

| URL Target | Final Score | Threshold | Verdict | Latency (ms) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `https://google.com` | 0.0 | 10.0 | `ALLOW` | 60.20ms | PASS |
| `https://github.com` | 0.0 | 10.0 | `ALLOW` | 1.13ms | PASS |
| `https://microsoft.com` | 0.0 | 10.0 | `ALLOW` | 1.05ms | PASS |
| `https://paypal-security-update.com/login` | 31.0 | 10.0 | `BLOCK` | 10859.61ms | PASS |
| `https://login-chase-update.com` | 25.0 | 10.0 | `BLOCK` | 2932.57ms | PASS |
| `https://secure-pay.com/qr-auth` | 31.0 | 10.0 | `BLOCK` | 7385.30ms | PASS |
| `https://banking-portal.net/secure` | 31.0 | 10.0 | `BLOCK` | 2543.91ms | PASS |
| `https://xn--exmple-dua.com` | 15.0 | 10.0 | `BLOCK` | 5780.31ms | PASS |
| `https://bit.ly/chase-login` | 0.0 | 10.0 | `ALLOW` | 1.25ms | PASS |

## 2. Prioritized Explanation Signals Trace

### `https://google.com`
- Reasons:

### `https://github.com`
- Reasons:

### `https://microsoft.com`
- Reasons:

### `https://paypal-security-update.com/login`
- Reasons:
  * "Structured LightGBM model predicted 100.0% phishing probability"
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"
  * "DOM: contains credentials harvesting input fields (password)"

### `https://login-chase-update.com`
- Reasons:
  * "Structured LightGBM model predicted 1.7% phishing probability"
  * "High hostname character entropy (3.84) indicates potential random string generation."
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"

### `https://secure-pay.com/qr-auth`
- Reasons:
  * "Structured LightGBM model predicted 100.0% phishing probability"
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"
  * "DOM: contains credentials harvesting input fields (password)"

### `https://banking-portal.net/secure`
- Reasons:
  * "Structured LightGBM model predicted 100.0% phishing probability"
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"
  * "DOM: contains credentials harvesting input fields (password)"

### `https://xn--exmple-dua.com`
- Reasons:
  * "Structured LightGBM model predicted 0.6% phishing probability"
  * "No WHOIS record found"

### `https://bit.ly/chase-login`
- Reasons:

