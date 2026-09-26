import logging
import sys

def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configures structured console logging for AlaviTrace.
    """
    logger = logging.getLogger("AlaviTrace")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid adding duplicate handlers if logger initialized multiple times
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        formatter = logging.Formatter(
            '[%(levelname)s] %(message)s'
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
