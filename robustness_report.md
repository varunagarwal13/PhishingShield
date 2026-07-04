# PhishingShield Robustness Tests Report

| Test Group Type | URL Target | Predicted Verdict | Latency (ms) | Status |
| :--- | :--- | :--- | :--- | :--- |
| Long URL | `https://paypal-security-update.com/login` | `BLOCK` | 5.05ms | PASS |
| Unicode | `https://xn--exmple-dua.com` | `ALLOW` | 3.32ms | PASS |
| Deep path / Query | `https://secure-chase-update-verification` | `BLOCK` | 6.45ms | PASS |
| IP Address | `http://127.0.0.1` | `BLOCK` | 2.18ms | PASS |
| URL Shortener | `https://bit.ly/chase-login` | `BLOCK` | 1.06ms | PASS |
