# PhishingShield Pipeline Trace Report

This report traces the execution states and outputs of all detectors for the targeted threat vectors.

## Target URL: `https://paypal-security-update.com/login`

- **Final Risk Score**: `31.0`
- **Action Verdict**: `BLOCK`
- **Prioritized Reasons**:
  * "Structured LightGBM model predicted 100.0% phishing probability"
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"
  * "DOM: contains credentials harvesting input fields (password)"

## Target URL: `https://login-chase-update.com`

- **Final Risk Score**: `25.0`
- **Action Verdict**: `BLOCK`
- **Prioritized Reasons**:
  * "Structured LightGBM model predicted 1.7% phishing probability"
  * "High hostname character entropy (3.84) indicates potential random string generation."
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"

## Target URL: `https://secure-pay.com/qr-auth`

- **Final Risk Score**: `31.0`
- **Action Verdict**: `BLOCK`
- **Prioritized Reasons**:
  * "Structured LightGBM model predicted 100.0% phishing probability"
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"
  * "DOM: contains credentials harvesting input fields (password)"

## Target URL: `https://banking-portal.net/secure`

- **Final Risk Score**: `31.0`
- **Action Verdict**: `BLOCK`
- **Prioritized Reasons**:
  * "Structured LightGBM model predicted 100.0% phishing probability"
  * "Page requests user authentication input (password field present)"
  * "Form submission points to mismatching non-brand domain target"
  * "DOM: contains credentials harvesting input fields (password)"

