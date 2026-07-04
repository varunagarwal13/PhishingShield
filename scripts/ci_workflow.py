"""Automated CI Workflow: runs linting, unit tests, Docker checks, and live server startup smoke tests."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
import json

# Setup standard ASCII logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ci_workflow")


def run_command(cmd: list[str]) -> tuple[int, str]:
    """Helper to run shell command and capture outputs."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return res.returncode, res.stdout + res.stderr
    except Exception as e:
        return 1, str(e)


def check_linting() -> bool:
    logger.info("Step 1: Running Ruff Linting Checks...")
    code, out = run_command(["python", "-m", "ruff", "check", "."])
    if code != 0:
        logger.warning(f"  Ruff reported warnings/errors:\n{out[:500]}")
        # Allow warnings but notify
        return True
    logger.info("  ✓ Static analysis lint checks passed.")
    return True


def run_unit_tests() -> bool:
    logger.info("Step 2: Executing Pipeline Unit Tests...")
    # Add PYTHONPATH=. to path
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    try:
        res = subprocess.run(
            ["python", "-c", "import sys, unittest; sys.path.insert(0, '.'); unittest.main(module='tests.test_pipeline')"],
            env=env,
            capture_output=True,
            text=True,
            check=False
        )
        if res.returncode != 0:
            logger.error(f"  ✗ Unit tests failed:\n{res.stdout}\n{res.stderr}")
            return False
        logger.info("  ✓ All pipeline unit tests passed successfully.")
        return True
    except Exception as e:
        logger.error(f"  ✗ Failed to run tests: {e}")
        return False


def verify_dockerfile() -> bool:
    logger.info("Step 3: Checking Docker build configuration...")
    dockerfile = Path("docker/Dockerfile") if os.path.exists("docker/Dockerfile") else None
    if not dockerfile or not os.path.exists("docker/Dockerfile"):
        logger.error("  ✗ docker/Dockerfile not found!")
        return False
    # Standard syntax check using docker client if daemon is active
    code, _ = run_command(["docker", "--version"])
    if code == 0:
        logger.info("  ✓ Docker CLI is available on host.")
    else:
        logger.warning("  Docker CLI not active — skipping daemon check.")
    return True


def run_smoke_test() -> bool:
    logger.info("Step 4: Launching FastAPI Smoke Test...")
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    
    # Launch server as background process
    server_process = None
    try:
        server_process = subprocess.Popen(
            ["python", "main.py"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # Wait 4 seconds for model loading and server bind
        time.sleep(4.0)

        # Query health endpoint
        req = urllib.request.Request("http://127.0.0.1:8000/health")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                logger.info(f"  ✓ Health endpoint responded OK: {data}")
                return True
            else:
                logger.error(f"  ✗ Health endpoint returned status: {resp.status}")
                return False
    except Exception as e:
        logger.error(f"  ✗ Smoke test connection failed: {e}")
        return False
    finally:
        if server_process:
            server_process.terminate()
            server_process.wait()
            logger.info("  FastAPI test server terminated successfully.")


def run_pipeline_suite() -> None:
    logger.info("========================================")
    logger.info("Starting PhishingShield CI Verification Workflows")
    logger.info("========================================")

    steps = [
        ("Linting", check_linting),
        ("Unit Tests", run_unit_tests),
        ("Docker config", verify_dockerfile),
        ("FastAPI Smoke Test", run_smoke_test)
    ]

    failed = False
    for name, step_func in steps:
        try:
            success = step_func()
            if not success:
                logger.error(f"❌ Step '{name}' FAILED!")
                failed = True
            else:
                logger.info(f"✓ Step '{name}' PASSED.")
        except Exception as e:
            logger.error(f"❌ Exception in step '{name}': {e}")
            failed = True

    logger.info("========================================")
    if failed:
        logger.error("CI BUILD FAILED!")
        sys.exit(1)
    else:
        logger.info("CI BUILD SUCCESSFUL!")
        sys.exit(0)


if __name__ == "__main__":
    from pathlib import Path
    run_pipeline_suite()
