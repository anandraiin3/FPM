"""Entry-point for Application 2: False Positive Minimizer."""
import argparse
import logging
import os
import sys

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="False Positive Minimizer")
    parser.add_argument("--max-alerts", type=int, default=None,
                        help="Process at most N alerts then exit (default: unlimited)")
    args = parser.parse_args()

    # Validate API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.error("OPENAI_API_KEY not set. Create a .env file or export it.")
        sys.exit(1)

    from openai import OpenAI

    openai_client = OpenAI(api_key=api_key)

    # Step 1: Build / load knowledge base
    logger.info("Initialising knowledge base...")
    from fpm.knowledge.builder import build_knowledge_base

    store = build_knowledge_base(openai_client)

    # Step 2: Initialise hybrid retriever
    logger.info("Initialising hybrid retriever...")
    from fpm.retrieval.hybrid_search import HybridRetriever

    retriever = HybridRetriever(store)

    # Step 3: Start polling loop
    logger.info("Starting FPM polling loop...")
    from fpm.polling import FPMPoller

    poller = FPMPoller(openai_client, retriever, max_alerts=args.max_alerts)
    try:
        poller.run()
    except KeyboardInterrupt:
        logger.info("FPM stopped by user")
        poller.stop()


if __name__ == "__main__":
    main()
