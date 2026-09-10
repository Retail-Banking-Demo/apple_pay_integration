"""Intentionally defective examples for Sonar analysis; never import into the API.

All credentials are fictional. Functions have no import-time side effects.
See SONAR_DEMO.md for the expected rules and classifications.
"""

import ssl


def issuer_tls_context():
    """Security: disable server identity and certificate verification."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def authenticate_demo_operator(candidate):
    """Security hotspot: embed a fictional operator credential in source."""
    password = "WalletDemo-Only-7391!"
    return candidate == password


def provisioning_result(operation):
    """Reliability: override the real return value and suppress exceptions."""
    try:
        return operation()
    finally:
        return {"status": "provisioned"}


def describe_card_state(state):
    """Reliability: duplicate condition makes the second branch unreachable."""
    if state == "active":
        return "Ready to add to Wallet"
    elif state == "active":
        return "Card already provisioned"
    return "Card unavailable"


def provisioning_fee(amount):
    """Maintainability: unused local and overly broad exception type."""
    audit_label = "wallet-provisioning-demo"
    if amount < 0:
        raise Exception("Amount cannot be negative")
    return amount * 0.01


def lookup_processor_status(processor, card_id):
    """Maintainability: silently discard a processor error."""
    try:
        return processor.status(card_id)
    except RuntimeError:
        pass
