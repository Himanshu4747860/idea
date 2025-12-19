import requests
import socket
import dns.resolver
import subprocess
import logging

# This module checks server/hosting for trust signals.
# Passive only.

def is_shared_ip(domain):
    """Basic heuristic: if IP resolves to multiple domains, assume shared. Returns 1 (shared), 0 (not), or None on failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Fallback DNS for Termux
        answers = resolver.resolve(domain)
        ip = answers[0].to_text()
        ptr_records = resolver.resolve_address(ip)
        if len(ptr_records) > 1:
            return 1
        return 0
    except Exception as e:
        logging.warning(f"Failed to check shared IP for {domain}: {e}")
    return None

def get_hosting_provider(domain):
    """Get ASN/provider name via WHOIS on IP. Returns string or None."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        answers = resolver.resolve(domain)
        ip = answers[0].to_text()
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if 'origin' in line.lower() or 'asn' in line.lower():
                return line.strip()
        return "Unknown"
    except Exception as e:
        logging.warning(f"Failed to get hosting provider for {domain}: {e}")
    return None

def has_security_headers(domain):
    """Check for basic security headers (e.g., CSP, HSTS). Returns 1 (present), 0 (not), or None."""
    try:
        response = requests.get(f"https://{domain}", timeout=5, headers={'User-Agent': 'Demo Scanner'})
        headers = response.headers
        security_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options']
        if any(h in headers for h in security_headers):
            return 1
        return 0
    except Exception as e:
        logging.warning(f"Failed to check security headers for {domain}: {e}")
    return None

def is_server_exposed(domain):
    """Check if Server header exposes version. Returns 1 (exposed), 0 (not), or None."""
    try:
        response = requests.get(f"https://{domain}", timeout=5, headers={'User-Agent': 'Demo Scanner'})
        if 'Server' in response.headers and '/' in response.headers['Server']:
            return 1
        return 0
    except Exception as e:
        logging.warning(f"Failed to check server exposure for {domain}: {e}")
    return None
