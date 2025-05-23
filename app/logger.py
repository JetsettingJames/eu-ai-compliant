import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)  # Log to stdout
    ]
)

# Get a logger instance
def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

# Example usage (optional, can be removed):
# if __name__ == "__main__":
#     logger = get_logger(__name__)
#     logger.info("Logger initialized and working.")
#     logger.warning("This is a warning message.")
#     logger.error("This is an error message.")
