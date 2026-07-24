# Clean file — no secrets, only placeholders.
# Used by tests to verify that SecretGuard does NOT flag safe code.

import os

# These are all placeholders — should be classified as LOW / ignored.
api_key = "YOUR_API_KEY_HERE"
database_url = "example_connection_string"
secret_key = "REPLACE_ME"
auth_token = "<INSERT_TOKEN>"
password = "changeme"

# Short values — below min_secret_length, should be skipped entirely.
token = "abc"
key = "test"

# Environment variable references — safe.
real_api_key = os.environ.get("API_KEY", "")

print("This file contains no real secrets.")
