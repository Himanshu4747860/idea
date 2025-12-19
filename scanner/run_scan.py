import sqlite3
import datetime
import logging
from scanner.domain import get_domain_age, get_domain_expiry_days
from scanner.dns_check import has_spf, has_dmarc
from scanner.ssl_check import has_https, get_cert_valid_days
from scanner.server import is_shared_ip, get_hosting_provider, has_security_headers, is_server_exposed

logging.basicConfig(level=logging.INFO)

SITES = ['example.com', 'github.com', 'cloudflare.com', 'wikipedia.org', 'python.org', 'mozilla.org']
DB_PATH = 'data/scans.db'

def create_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        domain_age INTEGER,
        domain_expiry_days INTEGER,
        spf INTEGER,
        dmarc INTEGER,
        https INTEGER,
        cert_valid_days INTEGER,
        shared_ip INTEGER,
        hosting_provider TEXT,
        security_headers INTEGER,
        server_exposed INTEGER,
        scanned_at TEXT
    )''')
    conn.commit()
    conn.close()

def scan_domain(domain):
    return {
        'domain': domain,
        'domain_age': get_domain_age(domain),
        'domain_expiry_days': get_domain_expiry_days(domain),
        'spf': has_spf(domain),
        'dmarc': has_dmarc(domain),
        'https': has_https(domain),
        'cert_valid_days': get_cert_valid_days(domain),
        'shared_ip': is_shared_ip(domain),
        'hosting_provider': get_hosting_provider(domain),
        'security_headers': has_security_headers(domain),
        'server_exposed': is_server_exposed(domain),
        'scanned_at': datetime.datetime.now(datetime.timezone.utc).isoformat()  # Fixed deprecation
    }

def insert_results(results):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''INSERT INTO scans (
        domain, domain_age, domain_expiry_days, spf, dmarc, https, cert_valid_days,
        shared_ip, hosting_provider, security_headers, server_exposed, scanned_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
        results['domain'], results['domain_age'], results['domain_expiry_days'],
        results['spf'], results['dmarc'], results['https'], results['cert_valid_days'],
        results['shared_ip'], results['hosting_provider'], results['security_headers'],
        results['server_exposed'], results['scanned_at']
    ))
    conn.commit()
    conn.close()

def generate_demo_report():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 6")
    rows = cursor.fetchall()
    conn.close()
    
    with open('reports/demo_report.txt', 'w') as f:
        f.write("Demo Data - Latest Scan Results\n")
        f.write("================================\n")
        for row in rows:
            f.write(f"Domain: {row[1]}, Scanned: {row[12]}\n")
            f.write(f"  Age: {row[2]}, Expiry Days: {row[3]}, SPF: {row[4]}, DMARC: {row[5]}\n")
            f.write(f"  HTTPS: {row[6]}, Cert Days: {row[7]}, Shared IP: {row[8]}, Provider: {row[9]}\n")
            f.write(f"  Security Headers: {row[10]}, Server Exposed: {row[11]}\n\n")

def main():
    create_table()
    for site in SITES:
        logging.info(f"Scanning {site}")
        results = scan_domain(site)
        insert_results(results)
    generate_demo_report()
    logging.info("Scan complete. Demo data updated.")

if __name__ == '__main__':
    main()
