# External Dataset Phishing Evaluation Report

- **Total URLs Evaluated**: `57975`
- **Assumed Ground-Truth**: `100.0% Phishing` (All URLs treated as phishing)
- **True Positives (Detected)**: `44800`
- **False Negatives (Missed)**: `13175`
- **Detection Rate (Sensitivity)**: `77.2747%`
- **Average Model Confidence**: `97.8072%`

## 1. Prediction Probability Distribution

| Probability Range | Sample Count | Percentage |
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

## 2. Top 100 Missed Phishing URLs (False Negatives)

Below are the 100 URLs with the lowest predicted phishing probabilities, along with their feature analysis:

| Rank | URL | Probability | Benign Feature Contributions / Explanation |
| :--- | :--- | :--- | :--- |
| 1 | `http://aave-v4.net` | 0.00% | suspicious_keywords=0, low_entropy=2.24, punycode=0, mixed_scripts=0, unicode=0 |
| 2 | `http://13cp1.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 3 | `http://13814.com` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 4 | `http://am.app8.in` | 0.00% | suspicious_keywords=0, low_entropy=1.50, punycode=0, mixed_scripts=0, unicode=0 |
| 5 | `http://20i.co.in` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 6 | `http://551002.co` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 7 | `http://22c.mobi` | 0.00% | suspicious_keywords=0, low_entropy=0.92, punycode=0, mixed_scripts=0, unicode=0 |
| 8 | `http://2268.site` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.50, punycode=0, mixed_scripts=0 |
| 9 | `http://37435.mba` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 10 | `http://370363.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.79, punycode=0, mixed_scripts=0 |
| 11 | `http://3676a.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 12 | `http://3hdr0.za.com` | 0.00% | suspicious_keywords=0, low_entropy=1.00, punycode=0, mixed_scripts=0, unicode=0 |
| 13 | `http://00877.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.52, punycode=0, mixed_scripts=0 |
| 14 | `http://60k70.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 15 | `http://60xd.vip` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 16 | `http://3656b.vip` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 17 | `http://amaic.xyz` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 18 | `http://ab-tdod3.gq` | 0.00% | suspicious_keywords=0, low_entropy=2.75, punycode=0, mixed_scripts=0, unicode=0 |
| 19 | `http://551001.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0 |
| 20 | `http://24202.top` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.37, punycode=0, mixed_scripts=0 |
| 21 | `http://54f6.xyz` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 22 | `http://54565.top` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.37, punycode=0, mixed_scripts=0 |
| 23 | `http://2025a.my.id` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 24 | `http://551004.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 25 | `http://551003.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 26 | `http://87hg8.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 27 | `http://365qq.com` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 28 | `http://23303.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.37, punycode=0, mixed_scripts=0 |
| 29 | `http://ama96.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 30 | `http://am6mm.com` | 0.00% | suspicious_keywords=0, low_entropy=1.37, punycode=0, mixed_scripts=0, unicode=0 |
| 31 | `https://ff-io.to` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 32 | `http://36564.tv` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 33 | `http://aagvn.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 34 | `http://551005.co` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.46, punycode=0, mixed_scripts=0 |
| 35 | `http://551005.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.46, punycode=0, mixed_scripts=0 |
| 36 | `http://66014.uno` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 37 | `http://65u3.info` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 38 | `http://a608.cc` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 39 | `http://a5.oyzb.link` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 40 | `http://a-86.one` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 41 | `http://666489.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.79, punycode=0, mixed_scripts=0 |
| 42 | `http://666314.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.79, punycode=0, mixed_scripts=0 |
| 43 | `http://5365s.xyz` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 44 | `http://5365.pw` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.50, punycode=0, mixed_scripts=0 |
| 45 | `http://3day-cna.com` | 0.00% | suspicious_keywords=0, low_entropy=2.75, punycode=0, mixed_scripts=0, unicode=0 |
| 46 | `http://878fa.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 47 | `https://ff-io.cc` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 48 | `http://24en.site` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 49 | `http://551004.me` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 50 | `http://888415.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.79, punycode=0, mixed_scripts=0 |
| 51 | `http://888235.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.79, punycode=0, mixed_scripts=0 |
| 52 | `http://886ko.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 53 | `http://2.656602.com` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.79, punycode=0, mixed_scripts=0 |
| 54 | `http://36563.tv` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.52, punycode=0, mixed_scripts=0 |
| 55 | `http://551006.co` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 56 | `http://551005.me` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.46, punycode=0, mixed_scripts=0 |
| 57 | `https://ff-io.at` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 58 | `http://66255.vip` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.52, punycode=0, mixed_scripts=0 |
| 59 | `http://6619m.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 60 | `http://25433.top` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 61 | `http://250160.8b.io` | 0.00% | suspicious_keywords=0, low_entropy=1.00, punycode=0, mixed_scripts=0, unicode=0 |
| 62 | `http://25th.rs` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 63 | `http://3656cc.cc` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 64 | `http://aa-in.icu` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 65 | `http://89511.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 66 | `http://88oao.com` | 0.00% | suspicious_keywords=0, low_entropy=1.52, punycode=0, mixed_scripts=0, unicode=0 |
| 67 | `http://5165456464infonotification.ml` | 0.00% | suspicious_keywords=0, punycode=0, mixed_scripts=0, unicode=0, safe_tld |
| 68 | `http://50g.ci16.xyz` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 69 | `http://50g.cd83.xyz` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 70 | `http://2bcit.org.ru` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 71 | `http://2bcit.net.ru` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 72 | `http://29962.top` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.52, punycode=0, mixed_scripts=0 |
| 73 | `http://40.aaab.su` | 0.00% | suspicious_keywords=0, low_entropy=0.81, punycode=0, mixed_scripts=0, unicode=0 |
| 74 | `http://a365.vip` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 75 | `http://akonaa.fr` | 0.00% | suspicious_keywords=0, low_entropy=1.79, punycode=0, mixed_scripts=0, unicode=0 |
| 76 | `http://282434.cc` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 77 | `http://al882.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 78 | `http://2015.sa.com` | 0.00% | suspicious_keywords=0, low_entropy=1.00, punycode=0, mixed_scripts=0, unicode=0 |
| 79 | `http://3656c.cc` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 80 | `http://2021p.cn` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 81 | `http://551008.me` | 0.00% | brand_similarity=0.0, suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0 |
| 82 | `http://2bint.pp.ru` | 0.00% | suspicious_keywords=0, low_entropy=-0.00, punycode=0, mixed_scripts=0, unicode=0 |
| 83 | `http://2bint.org.ru` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 84 | `http://365l3.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 85 | `https://v3-yearn.org` | 0.00% | suspicious_keywords=0, punycode=0, mixed_scripts=0, unicode=0, safe_tld |
| 86 | `http://a.365kdhk.cc` | 0.00% | suspicious_keywords=0, low_entropy=2.52, punycode=0, mixed_scripts=0, unicode=0 |
| 87 | `http://aave-v3a.com` | 0.00% | suspicious_keywords=0, low_entropy=2.16, punycode=0, mixed_scripts=0, unicode=0 |
| 88 | `http://aave.navy` | 0.00% | suspicious_keywords=0, low_entropy=1.50, punycode=0, mixed_scripts=0, unicode=0 |
| 89 | `http://aave.lv` | 0.00% | suspicious_keywords=0, low_entropy=1.50, punycode=0, mixed_scripts=0, unicode=0 |
| 90 | `http://aavee.net` | 0.00% | suspicious_keywords=0, low_entropy=1.52, punycode=0, mixed_scripts=0, unicode=0 |
| 91 | `http://a-ave.com` | 0.00% | suspicious_keywords=0, low_entropy=1.92, punycode=0, mixed_scripts=0, unicode=0 |
| 92 | `http://aave.co.in` | 0.00% | suspicious_keywords=0, low_entropy=1.50, punycode=0, mixed_scripts=0, unicode=0 |
| 93 | `http://2bikt.org.ru` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 94 | `http://2bikt.net.ru` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 95 | `http://2bict.net.ru` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 96 | `http://1-z.com` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 97 | `http://8fd.me` | 0.00% | suspicious_keywords=0, low_entropy=1.58, punycode=0, mixed_scripts=0, unicode=0 |
| 98 | `http://8ntp.icu` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 99 | `http://50g.cd41.xyz` | 0.00% | suspicious_keywords=0, low_entropy=2.00, punycode=0, mixed_scripts=0, unicode=0 |
| 100 | `http://2bikt.pp.ru` | 0.00% | suspicious_keywords=0, low_entropy=-0.00, punycode=0, mixed_scripts=0, unicode=0 |
