"""FastAPI main application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import joblib
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware import request_context_middleware
from app.api.routes import router as api_router
from app.database.connection import init_db
from config.logging import configure_logging

configure_logging(level=logging.INFO)
logger = logging.getLogger("phishing_shield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Initialize Database ──
    logger.info("Initializing database...")
    init_db()
    logger.info("✓ Database initialized successfully")

    # ── Load ML and NLP Models (with stubs if files not present) ──
    logger.info("Loading models...")
    
    # 1. Random Forest Classifier
    try:
        app.state.rf = joblib.load("model_rf_v2.pkl")
        logger.info("✓ model_rf_v2.pkl loaded successfully")
    except FileNotFoundError:
        app.state.rf = None
        logger.warning("⚠ model_rf_v2.pkl not found — ML check will run in stub mode")

    # 2. XGBoost Classifier
    try:
        app.state.xgb = joblib.load("model_xgb_v2.pkl")
        logger.info("✓ model_xgb_v2.pkl loaded successfully")
    except FileNotFoundError:
        app.state.xgb = None
        logger.warning("⚠ model_xgb_v2.pkl not found — ML check will run in stub mode")

    # 3. Feature Columns List
    try:
        app.state.FEATURE_COLS = joblib.load("feature_cols_v2.pkl")
        logger.info(f"✓ feature_cols_v2.pkl loaded ({len(app.state.FEATURE_COLS)} features)")
    except FileNotFoundError:
        app.state.FEATURE_COLS = []
        logger.warning("⚠ feature_cols_v2.pkl not found — ML feature mapping empty")

    # 4. NLP Vectorizer & Model
    try:
        app.state.nlp_vectorizer = joblib.load("nlp_vectorizer.pkl")
        app.state.nlp_clf = joblib.load("nlp_model.pkl")
        app.state.NLP_ENABLED = True
        logger.info("✓ NLP model & vectorizer loaded successfully")
    except FileNotFoundError:
        app.state.NLP_ENABLED = False
        logger.warning("⚠ NLP model files not found — page content NLP checks disabled")
    except Exception as e:
        app.state.NLP_ENABLED = False
        logger.error(f"Failed to load NLP models: {e}")

    yield

    logger.info("Server shutting down")


# ── Initialize FastAPI ──
app = FastAPI(title="Phishing Shield API", version="2.0.0", lifespan=lifespan)

# Add CORS Middleware to support extension and local dashboard requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*", "http://127.0.0.1", "http://localhost", "*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Register request middleware and routes
app.middleware("http")(request_context_middleware)
app.include_router(api_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
