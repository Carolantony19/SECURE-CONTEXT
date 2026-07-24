# Leaky file — contains fake high-entropy "secrets" for testing.
# ALL values here are obviously fake and non-functional.

# Fake API key with high entropy (should trigger HIGH risk)
api_key = "sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCqRtMvAeYu"

# Fake database password (high entropy, sensitive variable name)
db_password = "xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGk"

# Fake token (high entropy, matches token pattern)
auth_token = "token_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"

# Fake AWS secret key (high entropy)
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake Stripe key
stripe_key = "fake_stripe_key_xK9mNpQ7rT2wU5yZ8cE1fH4jL"

# This one is a placeholder — should NOT be flagged as HIGH.
slack_token = "YOUR_SLACK_TOKEN_HERE"
