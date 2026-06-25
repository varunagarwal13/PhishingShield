import json
from pathlib import Path

import joblib


class ModelRegistry:
    def __init__(self, manifest_path="model_manifest.json"):
        self.manifest_path = Path(manifest_path)
        self.manifest = self._load_manifest()
        self.active_version = self.manifest.get("active_version", "v2")
        self.active_config = self.manifest["models"][self.active_version]

    def _load_manifest(self):
        if not self.manifest_path.exists():
            return {
                "active_version": "v2",
                "models": {
                    "v2": {
                        "rf": "model_rf_v2.pkl",
                        "xgb": "model_xgb_v2.pkl",
                        "feature_columns": "feature_cols_v2.pkl",
                        "nlp_model": "nlp_model.pkl",
                        "nlp_vectorizer": "nlp_vectorizer.pkl",
                    }
                },
            }
        with self.manifest_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def load_core_models(self):
        rf = joblib.load(self.active_config["rf"])
        xgb = joblib.load(self.active_config["xgb"])
        feature_cols = joblib.load(self.active_config["feature_columns"])
        return rf, xgb, feature_cols

    def load_nlp_models(self):
        nlp_model = self.active_config.get("nlp_model")
        nlp_vectorizer = self.active_config.get("nlp_vectorizer")
        if not nlp_model or not nlp_vectorizer:
            return None, None, False
        try:
            return joblib.load(nlp_vectorizer), joblib.load(nlp_model), True
        except Exception:
            return None, None, False

    def metadata(self):
        return {
            "active_version": self.active_version,
            "artifacts": dict(self.active_config),
        }
