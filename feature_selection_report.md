# PhishingShield Automated Feature Selection & Engineering Report

- **Initial Feature Space Size**: `104` features
- **Pruned Feature Space Size**: `77` features
- **Total Removed Features**: `27` features

## 1. Top 25 Retained Features by Importance (Mutual Info)

| Rank | Feature Column | Mutual Info Score | Status |
| :--- | :--- | :--- | :--- |
| 1 | `path_len` | 0.680317 | Retained |
| 2 | `path_complexity` | 0.679782 | Retained |
| 3 | `sim_keyboard_yahoo` | 0.391220 | Retained |
| 4 | `sim_keyboard_paypal` | 0.385730 | Retained |
| 5 | `sim_keyboard_adobe` | 0.384853 | Retained |
| 6 | `consecutive_consonant_ratio` | 0.384277 | Retained |
| 7 | `sim_keyboard_steam` | 0.372783 | Retained |
| 8 | `sim_keyboard_apple` | 0.370760 | Retained |
| 9 | `entropy` | 0.367087 | Retained |
| 10 | `sim_keyboard_google` | 0.366353 | Retained |
| 11 | `sim_keyboard_chase` | 0.363068 | Retained |
| 12 | `sim_jarowinkler_coinbase` | 0.355253 | Retained |
| 13 | `sim_keyboard_amazon` | 0.355134 | Retained |
| 14 | `sim_keyboard_linkedin` | 0.352101 | Retained |
| 15 | `sim_jarowinkler_linkedin` | 0.349874 | Retained |
| 16 | `sim_jarowinkler_netflix` | 0.343975 | Retained |
| 17 | `sim_keyboard_github` | 0.336685 | Retained |
| 18 | `sim_keyboard_netflix` | 0.331007 | Retained |
| 19 | `sim_jarowinkler_bankofamerica` | 0.329461 | Retained |
| 20 | `sim_keyboard_dropbox` | 0.319254 | Retained |
| 21 | `sim_keyboard_metamask` | 0.316991 | Retained |
| 22 | `sim_jarowinkler_microsoft` | 0.314673 | Retained |
| 23 | `sim_keyboard_microsoft` | 0.310770 | Retained |
| 24 | `sim_jarowinkler_instagram` | 0.309785 | Retained |
| 25 | `sim_keyboard_facebook` | 0.308959 | Retained |

## 2. Removed Features List

| Feature Column | Mutual Info Score | Pruning Reason |
| :--- | :--- | :--- |
| `numeric_hostname_ratio` | 0.285830 | High Correlation |
| `bigram_entropy` | 0.221501 | High Correlation |
| `trigram_entropy` | 0.180409 | High Correlation |
| `tld_rarity_score` | 0.000000 | Low Mutual Information |
| `query_complexity` | 0.011553 | High Correlation |
| `fragment_complexity` | 0.000000 | Low Mutual Information |
| `suspicious_parameter_names` | 0.000000 | Low Mutual Information |
| `sim_homoglyph_paypal` | 0.199440 | High Correlation |
| `sim_homoglyph_google` | 0.193432 | High Correlation |
| `sim_homoglyph_amazon` | 0.142716 | High Correlation |
| `sim_homoglyph_facebook` | 0.222645 | High Correlation |
| `sim_homoglyph_netflix` | 0.222406 | High Correlation |
| `sim_homoglyph_apple` | 0.196956 | High Correlation |
| `sim_homoglyph_microsoft` | 0.155636 | High Correlation |
| `sim_homoglyph_instagram` | 0.152606 | High Correlation |
| `sim_homoglyph_twitter` | 0.139176 | High Correlation |
| `sim_homoglyph_linkedin` | 0.242820 | High Correlation |
| `sim_homoglyph_chase` | 0.186609 | High Correlation |
| `sim_homoglyph_wellsfargo` | 0.213247 | High Correlation |
| `sim_homoglyph_bankofamerica` | 0.255829 | High Correlation |
| `sim_homoglyph_coinbase` | 0.206182 | High Correlation |
| `sim_homoglyph_metamask` | 0.161880 | High Correlation |
| `sim_homoglyph_yahoo` | 0.115871 | High Correlation |
| `sim_homoglyph_github` | 0.101923 | High Correlation |
| `sim_homoglyph_steam` | 0.189907 | High Correlation |
| `sim_homoglyph_adobe` | 0.232771 | High Correlation |
| `sim_homoglyph_dropbox` | 0.125329 | High Correlation |

## 3. Retained Feature Names List

```json
[
  "url_len",
  "host_len",
  "path_len",
  "query_len",
  "fragment_len",
  "tld_len",
  "registered_domain_len",
  "subdomain_depth",
  "has_ip",
  "consecutive_consonant_ratio",
  "consecutive_digit_ratio",
  "entropy",
  "char_transition_entropy",
  "path_complexity",
  "param_count",
  "redirect_keyword_count",
  "phishing_keyword_count",
  "sim_levenshtein_paypal",
  "sim_jarowinkler_paypal",
  "sim_keyboard_paypal",
  "sim_levenshtein_google",
  "sim_jarowinkler_google",
  "sim_keyboard_google",
  "sim_levenshtein_amazon",
  "sim_jarowinkler_amazon",
  "sim_keyboard_amazon",
  "sim_levenshtein_facebook",
  "sim_jarowinkler_facebook",
  "sim_keyboard_facebook",
  "sim_levenshtein_netflix",
  "sim_jarowinkler_netflix",
  "sim_keyboard_netflix",
  "sim_levenshtein_apple",
  "sim_jarowinkler_apple",
  "sim_keyboard_apple",
  "sim_levenshtein_microsoft",
  "sim_jarowinkler_microsoft",
  "sim_keyboard_microsoft",
  "sim_levenshtein_instagram",
  "sim_jarowinkler_instagram",
  "sim_keyboard_instagram",
  "sim_levenshtein_twitter",
  "sim_jarowinkler_twitter",
  "sim_keyboard_twitter",
  "sim_levenshtein_linkedin",
  "sim_jarowinkler_linkedin",
  "sim_keyboard_linkedin",
  "sim_levenshtein_chase",
  "sim_jarowinkler_chase",
  "sim_keyboard_chase",
  "sim_levenshtein_wellsfargo",
  "sim_jarowinkler_wellsfargo",
  "sim_keyboard_wellsfargo",
  "sim_levenshtein_bankofamerica",
  "sim_jarowinkler_bankofamerica",
  "sim_keyboard_bankofamerica",
  "sim_levenshtein_coinbase",
  "sim_jarowinkler_coinbase",
  "sim_keyboard_coinbase",
  "sim_levenshtein_metamask",
  "sim_jarowinkler_metamask",
  "sim_keyboard_metamask",
  "sim_levenshtein_yahoo",
  "sim_jarowinkler_yahoo",
  "sim_keyboard_yahoo",
  "sim_levenshtein_github",
  "sim_jarowinkler_github",
  "sim_keyboard_github",
  "sim_levenshtein_steam",
  "sim_jarowinkler_steam",
  "sim_keyboard_steam",
  "sim_levenshtein_adobe",
  "sim_jarowinkler_adobe",
  "sim_keyboard_adobe",
  "sim_levenshtein_dropbox",
  "sim_jarowinkler_dropbox",
  "sim_keyboard_dropbox"
]
```
