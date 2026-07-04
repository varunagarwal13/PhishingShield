# PhishingShield Production False Negative Analysis

This document profiles model misses, clustering them by features to analyze structural bypass vectors.

## 1. Misses Clustering Overview

| Failure Cluster Group | Sample Misses Count | Primary Cause | Proposed Feature Solution |
| :--- | :--- | :--- | :--- |
| **short domains** | 206 | Domain string contains too few characters to capture similarity patterns. | Incorporate subdomain depth checks. |
| **numeric domains** | 157 | DGA or IP domain strings lack standard lexical word tokens. | Utilize character transitions matrices. |
| **parked domains** | 22 | Heuristics resemble clean default parked names page formats. | Incorporate browser behavior and redirects depth. |
| **no brand words** | 395 | Obfuscated target links do not contain brand spoof keywords. | Leverage content analysis NLP classifiers. |
| **low entropy** | 11 | Subdomains resemble flat simple dictionary names. | Apply Jaro-Winkler homoglyph cleaning checks. |
| **URL shorteners** | 73 | Redirect link services obscure true final destination paths. | Resolve destination URL before feature extraction. |
| **IP hosts** | 0 | Bypasses standard TLD validation heuristics. | Trigger threat intelligence lookups on raw IP blocks. |
| **uncommon TLDs** | 45 | Rare registry domains that have low frequency distributions. | Incorporate TLD rarity score mapping. |
| **redirectors** | 1 | Heuristics hide phishing path within valid redirect structures. | Extract features from path segments and query keys. |

## 2. Sample Failure Signatures List

### short domains Sample Targets
- `http://1st-20i.pages.dev`
- `http://504e1c2c.host.njalla.net`
- `http://8138fc2a-53bf-44db-91bf-80364d29735a.id.repl.co`

### numeric domains Sample Targets
- `http://36ketp56.me`
- `http://5510000.top`
- `http://3guq.sap28706z2.cc`

### parked domains Sample Targets
- `http://amazonl3.vip`
- `http://amazon.co.jp.qwezxccveretret1dvcbcvb.monster`
- `http://amazon-id.invesibletint.workers.dev`

### no brand words Sample Targets
- `http://165shopttk.com`
- `http://5gjtjgwff2f2f22f.blogspot.is`
- `http://54taizifei.com`

### low entropy Sample Targets
- `http://816.agromagazo.gr`
- `http://a.fgrehrr.com`
- `http://adhere-8091621098.zoesbeer.com`

### URL shorteners Sample Targets
- `http://23gg333333.blogspot.com`
- `http://24gewf232.blogspot.com`
- `http://310051-dot-n-e-w-me-ss-age-po-rt-al.wl.r.appspot.com`

### IP hosts Sample Targets
- *Zero misses recorded in this cluster group*

### uncommon TLDs Sample Targets
- `http://account-update.amazon.co.jp.customerservice-manage.top`
- `http://a.maxlsvlps.cc`
- `http://3i6j5kkl.xyz`

### redirectors Sample Targets
- `http://amz-userverify.redirectme.net`

