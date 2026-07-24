# service.py — Cross-module propagation
from config import SECRET_KEY
from logger import log_auth

def authenticate():
    token = SECRET_KEY
    log_auth(token)
