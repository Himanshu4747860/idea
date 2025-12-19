import ssl
import socket
import datetime
import logging

# This module checks SSL for HTTPS trust signals.
# Passive only.

def has_https(domain):
    """Check if HTTPS is enabled. Returns 1 (true), 0 (false), or None on failure."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return 1
    except Exception as e:
        logging.warning(f"Failed to check HTTPS for {domain}: {e}")
        return 0
    return None

def get_cert_valid_days(domain):
    """Get days until cert expiry. Returns int or None on failure."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert['notAfter']
                expiry = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                days = (expiry - datetime.datetime.now()).days
                return max(0, days)
    except Exception as e:
        logging.warning(f"Failed to get cert expiry for {domain}: {e}")
    return None
