"""Demo app — simulates a developer who replaced an AI placeholder with a real key."""

import os

# ⚠️ This is a FAKE secret for demonstration purposes only.
# In a real project, this would be a genuine API key that SecretGuard should catch.
api_key = "sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCq"

# This database URL contains an embedded fake password.
database_url = "postgresql://admin:xK9mNpQ7rT2wU5yZ@localhost:5432/mydb"


def connect():
    """Connect to the API (demo only — not functional)."""
    print(f"Connecting with key: {api_key[:8]}...")


if __name__ == "__main__":
    connect()
