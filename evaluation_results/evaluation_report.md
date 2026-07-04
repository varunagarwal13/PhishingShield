# Independent External Model Evaluation Report

This report validates the PhishingShield ML model on an unseen external benchmark dataset.

## 1. Dataset Characteristics

- **File Path**: `C:\Users\varun\OneDrive\Desktop\urls.txt`
- **Dataset Format**: `URL only`
- **Total URLs**: `57975`
- **Unique URLs**: `57975`
- **Duplicate URLs**: `0`
- **Unique Domains**: `38730`
- **Malformed/Unparsable URLs**: `0`
- **Labels Present**: `False (Inference-only evaluation performed)`

## 2. Model Parameters & Schema Verification

- **Model Version**: `2.0.0`
- **Calibration**: `CalibratedClassifierCV (isotonic regression)`
- **Feature Columns**: `url_len, host_len, path_len, query_len, param_count, digit_ratio, special_ratio, entropy, has_ip, non_standard_port, has_unicode, punycode, suspicious_tld, suspicious_keyword_count, brand_similarity_score, mixed_scripts`

## 3. Prediction Statistics & Distributions

- **Total Scanned**: `57975`
- **Predicted Phishing**: `44800 (77.27%)`
- **Predicted Benign**: `13175 (22.73%)`
- **Average Phishing Probability**: `77.97%`

### Probability Distribution Bins:

| Range | Sample Count | Percentage |
| :--- | :--- | :--- |
| 0% - 10% | 10323 | 17.81% |
| 10% - 20% | 1198 | 2.07% |
| 20% - 30% | 666 | 1.15% |
| 30% - 40% | 562 | 0.97% |
| 40% - 50% | 426 | 0.73% |
| 50% - 60% | 178 | 0.31% |
| 60% - 70% | 464 | 0.80% |
| 70% - 80% | 558 | 0.96% |
| 80% - 90% | 389 | 0.67% |
| 90% - 100% | 43211 | 74.53% |

### Model Confidence Distribution:

| Confidence Range | Sample Count | Percentage |
| :--- | :--- | :--- |
| 50% - 60% | 604 | 1.04% |
| 60% - 70% | 1026 | 1.77% |
| 70% - 80% | 1224 | 2.11% |
| 80% - 90% | 1587 | 2.74% |
| 90% - 100% | 53534 | 92.34% |

## 4. Top 100 Suspicious URLs (Highest Risk)

| Rank | URL | Probability |
| :--- | :--- | :--- |
| 1 | `http://0000h00003.byethost7.com/?i=1` | 100.00% |
| 2 | `http://0007854.atwebpages.com/desk/index.html` | 100.00% |
| 3 | `http://000l34e.wcomhost.com/?fbclid=IwAR0bTLKRzZoi5OU7l2Jy29nIPaepITsvtkgGMXlTLw...` | 100.00% |
| 4 | `http://000m8ih.wcomhost.com/mama/0f78b/index_2.html` | 100.00% |
| 5 | `http://000m8ih.wcomhost.com/mama/23a2c/index_2.html` | 100.00% |
| 6 | `http://000m8ih.wcomhost.com/mama/53c3e/index_2.html` | 100.00% |
| 7 | `http://000m8ih.wcomhost.com/mama/adee9/index_2.html` | 100.00% |
| 8 | `http://000m8ih.wcomhost.com/mama/c4fce/index_2.html` | 100.00% |
| 9 | `http://000m8ih.wcomhost.com/nass1/072b7/index_2.html` | 100.00% |
| 10 | `http://000m8ih.wcomhost.com/nass1/0dde4/index_2.html` | 100.00% |
| 11 | `http://000m8ih.wcomhost.com/nass1/19423/index_2.html` | 100.00% |
| 12 | `http://000m8ih.wcomhost.com/nass1/288f1/index_2.html` | 100.00% |
| 13 | `http://000m8ih.wcomhost.com/nass1/36388/index_2.html` | 100.00% |
| 14 | `http://000m8ih.wcomhost.com/nass1/44739/index_2.html` | 100.00% |
| 15 | `http://000m8ih.wcomhost.com/nass1/575bd/index_2.html` | 100.00% |
| 16 | `http://000m8ih.wcomhost.com/nass1/a2554/index_2.html` | 100.00% |
| 17 | `http://000m8ih.wcomhost.com/nass1/b412b/index_2.html` | 100.00% |
| 18 | `http://000m8ih.wcomhost.com/nass1/bec05/index_2.html` | 100.00% |
| 19 | `http://000m8ih.wcomhost.com/nass1/c5487/index_2.html` | 100.00% |
| 20 | `http://000m8ih.wcomhost.com/nass1/c6b64/index_2.html` | 100.00% |
| 21 | `http://000m8ih.wcomhost.com/nass1/fe249/index_2.html` | 100.00% |
| 22 | `http://000m8ih.wcomhost.com/papa/24083/index_2.html` | 100.00% |
| 23 | `http://000m8ih.wcomhost.com/papa/3d7bf/index_2.html` | 100.00% |
| 24 | `http://000m8ih.wcomhost.com/papa/98ed0/index_2.html` | 100.00% |
| 25 | `http://000m8ih.wcomhost.com/papa/b6f27/index_2.html` | 100.00% |
| 26 | `http://000m8ih.wcomhost.com/papa/c12e7/index_2.html` | 100.00% |
| 27 | `http://000m8ih.wcomhost.com/papa/c4eed/index_2.html` | 100.00% |
| 28 | `http://000nt6r.wcomhost.com/suspension/home/check/valid/access` | 100.00% |
| 29 | `http://000o2ba.wcomhost.com/mail/good/customer_center/customer-IDPP00C435/myacco...` | 100.00% |
| 30 | `http://000o2ba.wcomhost.com/mail/good/customer_center/customer-IDPP00C443/myacco...` | 100.00% |
| 31 | `http://000o5eh.wcomhost.com/admin/customer_center/customer-IDPP00C352/myaccount/...` | 100.00% |
| 32 | `http://000o5eh.wcomhost.com/logssss/customer_center/customer-IDPP00C332/myaccoun...` | 100.00% |
| 33 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 34 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 35 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 36 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 37 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 38 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 39 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 40 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 41 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 42 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 43 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 44 | `http://000o8dc.wcomhost.com/www.santanderbanco.es/bancosantander/es/particulares...` | 100.00% |
| 45 | `http://000ogwl.wcomhost.com/fasc/admin/customer_center/customer-IDPP00C963/myacc...` | 100.00% |
| 46 | `http://000ogwl.wcomhost.com/img/imager/png/customer_center/customer-IDPP00C378/m...` | 100.00% |
| 47 | `http://000ogxd.wcomhost.com/loggss/customer_center/customer-IDPP00C899/myaccount...` | 100.00% |
| 48 | `http://000ogxd.wcomhost.com/logs/customer_center/customer-IDPP00C557/myaccount/s...` | 100.00% |
| 49 | `http://000ogxd.wcomhost.com/logssss/customer_center/customer-IDPP00C196/myaccoun...` | 100.00% |
| 50 | `http://000ogxd.wcomhost.com/loogs/customer_center/customer-IDPP00C844/myaccount/...` | 100.00% |
| 51 | `http://000ogxd.wcomhost.com/mass/customer_center/customer-IDPP00C384/myaccount/s...` | 100.00% |
| 52 | `http://000ogxd.wcomhost.com/tops/customer_center/customer-IDPP00C176/myaccount/s...` | 100.00% |
| 53 | `http://000ogxd.wcomhost.com/tops/customer_center/customer-IDPP00C266/myaccount/s...` | 100.00% |
| 54 | `http://000ogxd.wcomhost.com/trustme/customer_center/customer-IDPP00C849` | 100.00% |
| 55 | `http://000oiq3.wcomhost.com/drunk/customer_center/customer-IDPP00C374/myaccount/...` | 100.00% |
| 56 | `http://000oiq3.wcomhost.com/GBTGNT24R4TTRH8TR5BHT5BHR5B5RT/TRGRTG5R1GVRF6V5G6R54...` | 100.00% |
| 57 | `http://000p0d5.wcomhost.com/AmeliAssurance/remboursement/login/iframe-page1.html` | 100.00% |
| 58 | `http://000p0dg.wcomhost.com/deadme/customer_center/customer-IDPP00C689/myaccount...` | 100.00% |
| 59 | `http://000p0dg.wcomhost.com/homelucky/customer_center/customer-IDPP00C889/myacco...` | 100.00% |
| 60 | `http://000p4en.wcomhost.com/Ameli-Assurance/remboursement/login` | 100.00% |
| 61 | `http://000p4en.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page1.htm...` | 100.00% |
| 62 | `http://000p4en.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page2.htm...` | 100.00% |
| 63 | `http://000p4en.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page3.htm...` | 100.00% |
| 64 | `http://000p6vl.wcomhost.com/Ameli-Assurance/remboursement/login` | 100.00% |
| 65 | `http://000p6vl.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page1.htm...` | 100.00% |
| 66 | `http://000p6vl.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page2.htm...` | 100.00% |
| 67 | `http://000p6vl.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page3.htm...` | 100.00% |
| 68 | `http://000p7l3.wcomhost.com/Ameli-Assurance/remboursement/login` | 100.00% |
| 69 | `http://000p7l3.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page1.htm...` | 100.00% |
| 70 | `http://000p7l3.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page2.htm...` | 100.00% |
| 71 | `http://000p7l3.wcomhost.com/Ameli-Assurance/remboursement/login/iframe-page3.htm...` | 100.00% |
| 72 | `http://000p8my.wcomhost.com/MobileFree/moncompte/0fb86c687f6cb25cbf1d9c191a2a123...` | 100.00% |
| 73 | `http://000p8my.wcomhost.com/MobileFree/moncompte/1e7fa6e7d7061724890964baebdc21c...` | 100.00% |
| 74 | `http://000p8my.wcomhost.com/MobileFree/moncompte/609ece9f991062e8013222f292181b4...` | 100.00% |
| 75 | `http://000p8my.wcomhost.com/MobileFree/moncompte/725244d964b68f9fd56edc530811d35...` | 100.00% |
| 76 | `http://000pbob.wcomhost.com/en-fr/systeme-` | 100.00% |
| 77 | `http://000pbox.wcomhost.com/Ameli-assurance/remboursement/login` | 100.00% |
| 78 | `http://000pbox.wcomhost.com/Ameli-assurance/remboursement/login/iframe-page1.htm...` | 100.00% |
| 79 | `http://000pbox.wcomhost.com/Ameli-assurance/remboursement/login/iframe-page2.htm...` | 100.00% |
| 80 | `http://000pbox.wcomhost.com/Ameli-assurance/remboursement/login/iframe-page3.htm...` | 100.00% |
| 81 | `http://000web-signon.4nmn.com/275ffad390cf0bc83bead9fc3682dfcf/contact404.php?to...` | 100.00% |
| 82 | `http://000web-signon.4nmn.com/275ffad390cf0bc83bead9fc3682dfcf/email1001.php?tok...` | 100.00% |
| 83 | `http://000web-signon.4nmn.com/275ffad390cf0bc83bead9fc3682dfcf/verify303.php?tok...` | 100.00% |
| 84 | `http://000web-signon.4nmn.com/b3ac3775e06cffcc7a4cbf5860f433cc/contact404.php?to...` | 100.00% |
| 85 | `http://000web-signon.4nmn.com/b3ac3775e06cffcc7a4cbf5860f433cc/email1001.php?tok...` | 100.00% |
| 86 | `http://000web-signon.4nmn.com/b3ac3775e06cffcc7a4cbf5860f433cc/verify303.php?tok...` | 100.00% |
| 87 | `http://000web-signon.4nmn.com/f6f3637f416e89b3ddcd9f91f4872e87/?token=7e2c43faaf...` | 100.00% |
| 88 | `http://001892.com/pages/tabbar/peidan/peidan` | 100.00% |
| 89 | `http://001983878188731stea8a1a0.myclickfunnels.com/31acc20172` | 100.00% |
| 90 | `http://004ca7f.netsolhost.com/godaddy/godaddy.php?24927eed531b3f78f73375d80614f3...` | 100.00% |
| 91 | `http://004ca7f.netsolhost.com/godaddy/sso.godaddy.comloginapp=email&realm=pass.p...` | 100.00% |
| 92 | `http://007a5701-5600-455b-84dc-c684b82e196b.s3.ap-northeast-2.amazonaws.com/!$&!...` | 100.00% |
| 93 | `http://00c85b59-4f3f-4376-8b3d-de07cf5249d3.htmlcomponentservice.com/get_draft?i...` | 100.00% |
| 94 | `http://00ca83f5-b7df-418d-ace5-e303a7e99cdf.htmlcomponentservice.com/get_draft?i...` | 100.00% |
| 95 | `http://00ca83f5-b7df-418d-ace5-e303a7e99cdf.htmlcomponentservice.com/get_draft?i...` | 100.00% |
| 96 | `http://00gty.ru.com/goldf/gbsources` | 100.00% |
| 97 | `http://00gty.ru.com/molp/AMENCN-1` | 100.00% |
| 98 | `http://00m-i-cloud.mipaginaweb.us/expire/index2.html` | 100.00% |
| 99 | `http://00pix.sa.com/login.php` | 100.00% |
| 100 | `http://00pozrjbpm.xyz/ap/signin?key=a@b.c&openid.assoc_handle=jpflex&openid.clai...` | 100.00% |
