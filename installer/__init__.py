import logging
import sys

LOG = logging.getLogger(__name__)

def fail(message):
    """Fails script with error message."""
    LOG.error(message)
    sys.exit(1)
