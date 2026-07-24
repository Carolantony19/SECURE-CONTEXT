# logger.py — Dangerous sink module
import logging

logger = logging.getLogger(__name__)

def log_auth(token):
    # DANGEROUS SINK: Secret printed/logged to output
    logger.info("Authenticating with token: %s", token)
