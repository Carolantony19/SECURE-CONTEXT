# SecretGuard-AI demo repository
# ─────────────────────────────
# This directory simulates a real project that a developer might scan
# with SecretGuard.  It contains:
#
#   app.py          — A "leaky" file with a fake secret (should BLOCK)
#   config_safe.py  — A clean file with only placeholders (should PASS)
#   settings.env    — An .env file with a fake leaked key
#
# Run the demo:
#     cd examples/demo_repo
#     secretguard scan .
#
# Expected output:
#     app.py:5        → HIGH (fake high-entropy key)
#     settings.env:1  → HIGH (fake high-entropy key in .env)
#     config_safe.py  → all LOW (placeholders)
