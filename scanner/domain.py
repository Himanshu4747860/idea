import whois
import datetime
import logging

# This module fetches WHOIS data for passive domain trust signals.
# Not a vulnerability scanner.

def get_domain_age(domain):
    """Calculate domain age in years. Returns int or None on failure."""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation = w.creation_date if isinstance(w.creation_date, datetime.datetime) else w.creation_date[0]
            age = (datetime.datetime.now() - creation).days // 365
            return age
    except Exception as e:
        logging.warning(f"Failed to get domain age for {domain}: {e}")
    return None

def get_domain_expiry_days(domain):
    """Calculate days until expiry. Returns int or None on failure."""
    try:
        w = whois.whois(domain)
        if w.expiration_date:
            expiry = w.expiration_date if isinstance(w.expiration_date, datetime.datetime) else w.expiration_date[0]
            days = (expiry - datetime.datetime.now()).days
            return max(0, days)  # No negative values
    except Exception as e:
        logging.warning(f"Failed to get domain expiry for {domain}: {e}")
    return None
