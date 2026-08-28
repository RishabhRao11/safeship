"""Safe fixture: correct credential handling. Zero findings expected.

Every line here contains a word the naive rules look for -- api_key, secret,
token, password -- attached to a value that is a reference, not a credential.
"""

import os
import getpass

from django.conf import settings

OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
SESSION_SECRET = settings.SESSION_SECRET
DB_PASSWORD = getpass.getpass("database password: ")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Stripe publishable keys are designed to ship in client code. Flagging one is
# a false positive, and this line exists to prove we do not.
STRIPE_PUBLISHABLE_KEY = "pk_live_51QpR7mNvXk2LaBcD9fHjT4wY"


def connect():
    return f"postgresql://{os.environ['DB_USER']}:{DB_PASSWORD}@{os.environ['DB_HOST']}/app"
