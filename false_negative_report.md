# PhishingShield False Negative Analysis

## 1. False Negative Cases Audit

Total False Negative Instances: `7551` (FNR of `29.557%`)

## 2. Weakness Clusters

- **Unicode / IDNA Spoofing**: Obfuscated characters bypass standard lexical entropy checks.
- **Shortened URL redirects**: Lexical classifiers evaluate shortener domains rather than final targets.
