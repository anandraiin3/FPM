"""Entry-point for Application 1: Traceable Mock Server."""
import logging
import os
import sys

# Ensure the project root is on sys.path so `mock_server.*` imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
import uvicorn

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

if __name__ == "__main__":
    uvicorn.run(
        "mock_server.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
