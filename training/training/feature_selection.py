"""Feature selection module using Mutual Information and correlation analysis."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import numpy as np
from sklearn.feature_selection import mutual_info_classif
from training.feature_engineering.features import extract_url_features, FEATURE_COLUMNS

logger = logging.getLogger("feature_selection")


def run_feature_selection(limit_samples: int = 4000) -> list[str]:
    logger.info("Starting automated feature selection analysis...")
    
    # 1. Load train split
    train_path = Path("training/validation/train_split.json")
    if not train_path.exists():
        raise FileNotFoundError("Train split not found. Run validation split stage first.")
        
    with open(train_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    # Sample subset for speed
    if len(data) > limit_samples:
        import random
        random.seed(42)
        data = random.sample(data, limit_samples)
        
    # 2. Extract features
    logger.info(f"Extracting features for {len(data)} selection samples...")
    X_list = []
    y_list = []
    for item in data:
        url = item["url"]
        label = item["label"]
        feat = extract_url_features(url)
        X_list.append([feat[col] for col in FEATURE_COLUMNS])
        y_list.append(label)
        
    X = np.array(X_list)
    y = np.array(y_list)
    
    # 3. Correlation Analysis (prune highly correlated features > 0.95)
    logger.info("Computing Pearson correlation matrix...")
    corr_matrix = np.corrcoef(X, rowvar=False)
    
    # Identify indices to drop
    dropped_corr_indices = set()
    for i in range(len(FEATURE_COLUMNS)):
        for j in range(i + 1, len(FEATURE_COLUMNS)):
            if abs(corr_matrix[i, j]) > 0.95:
                # Drop the feature with lower index (arbitrary rule)
                dropped_corr_indices.add(j)
                
    # 4. Mutual Information scores
    logger.info("Calculating Mutual Information scores...")
    mi_scores = mutual_info_classif(X, y, random_state=42)
    
    # Identify weak features (MI <= 0.001)
    dropped_mi_indices = set()
    for idx, score in enumerate(mi_scores):
        if score <= 0.001:
            dropped_mi_indices.add(idx)
            
    # Combine dropped features
    all_dropped_indices = dropped_corr_indices.union(dropped_mi_indices)
    
    retained_features = []
    removed_features = []
    importance_rankings = []
    
    for idx, col in enumerate(FEATURE_COLUMNS):
        importance_rankings.append((col, float(mi_scores[idx])))
        if idx in all_dropped_indices:
            reason = "High Correlation" if idx in dropped_corr_indices else "Low Mutual Information"
            removed_features.append((col, reason, float(mi_scores[idx])))
        else:
            retained_features.append(col)
            
    # Sort rankings
    importance_rankings.sort(key=lambda x: x[1], reverse=True)
    
    # Generate feature_selection_report.md
    report_path = Path("feature_selection_report.md")
    eng_report_path = Path("feature_engineering_report.md")
    logger.info(f"Writing feature selection report to {report_path}...")
    
    for rp in [report_path, eng_report_path]:
        with open(rp, "w", encoding="utf-8") as f:
            f.write("# PhishingShield Automated Feature Selection & Engineering Report\n\n")
            f.write(f"- **Initial Feature Space Size**: `{len(FEATURE_COLUMNS)}` features\n")
            f.write(f"- **Pruned Feature Space Size**: `{len(retained_features)}` features\n")
            f.write(f"- **Total Removed Features**: `{len(removed_features)}` features\n\n")
            
            f.write("## 1. Top 25 Retained Features by Importance (Mutual Info)\n\n")
            f.write("| Rank | Feature Column | Mutual Info Score | Status |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            rank = 1
            for col, score in importance_rankings:
                if col in retained_features and rank <= 25:
                    f.write(f"| {rank} | `{col}` | {score:.6f} | Retained |\n")
                    rank += 1
                    
            f.write("\n## 2. Removed Features List\n\n")
            f.write("| Feature Column | Mutual Info Score | Pruning Reason |\n")
            f.write("| :--- | :--- | :--- |\n")
            for col, reason, score in removed_features:
                f.write(f"| `{col}` | {score:.6f} | {reason} |\n")
                
            f.write("\n## 3. Retained Feature Names List\n\n")
            f.write("```json\n")
            f.write(json.dumps(retained_features, indent=2))
            f.write("\n```\n")
        
    logger.info("✓ Feature selection completed successfully.")
    return retained_features
