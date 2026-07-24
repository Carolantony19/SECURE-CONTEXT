"""Config file with safe placeholder values — should pass SecretGuard scan."""

import os

# All of these are AI-generated placeholders — safe to commit.
api_key = "YOUR_API_KEY_HERE"
secret_key = "<INSERT_SECRET_KEY>"
auth_token = "REPLACE_ME"
password = "example_password"

# Proper pattern: read from environment.
real_key = os.environ.get("API_KEY", "")
