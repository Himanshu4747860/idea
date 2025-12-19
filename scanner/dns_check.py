import dns.resolver
import logging

# This module checks DNS records for email trust signals.
# Passive only.

def has_spf(domain):
    """Check if SPF record exists. Returns 1 (true), 0 (false), or None on failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Fallback DNS for Termux
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf' in str(rdata):
                return 1
        return 0
    except Exception as e:
        logging.warning(f"Failed to check SPF for {domain}: {e}")
    return None

def has_dmarc(domain):
    """Check if DMARC record exists. Returns 1 (true), 0 (false), or None on failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            if 'v=DMARC' in str(rdata):
                return 1
        return 0
    except Exception as e:
        logging.warning(f"Failed to check DMARC for {domain}: {e}")
    return None
