#!/usr/bin/env python3

import os
import time
import json
import subprocess
import glob
import logging
import sqlite3
from datetime import datetime

# Configuration
PART_FILE_DIRECTORY = "/home/admin/muonfp/fingerprints/"  # Directory containing the .part files
LOG_FILE = "fpfwd.log"  # Log file for script activity
POLL_INTERVAL = 60  # Polling interval in seconds
DATABASE_FILE = "fpfwd.db"  # SQLite database file

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def setup_database():
    """Set up the SQLite database and create the necessary tables."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip_address TEXT NOT NULL,
                            fingerprint TEXT NOT NULL,
                            timestamp DATETIME NOT NULL,
                            UNIQUE(ip_address, fingerprint)
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            fingerprint TEXT NOT NULL,
                            action TEXT NOT NULL,
                            timestamp DATETIME,
                            UNIQUE(fingerprint, action)
                        )''')
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

def flag_fingerprint_for_removal(fingerprint):
    """Flag a fingerprint for removal by updating the fingerprints table."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO fingerprints (fingerprint, action) VALUES (?, 'remove')", (fingerprint,))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()
    print(f"Fingerprint {fingerprint} flagged for removal.")

def reconcile_nftables_with_db():
    """Reconcile nftables rules with the SQLite database."""
    try:
        command = "sudo nft -a list ruleset"
        logging.info(f"Running command: {command}")
        nft_output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True, check=True).stdout
        logging.info(f"nftables ruleset output: {nft_output}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to list nftables ruleset: {e}")
        return

    nft_rules = {}
    for line in nft_output.splitlines():
        if "inet filter input" in line:
            continue
        if "ip saddr" in line and "counter drop" in line:
            parts = line.split()
            ip = parts[parts.index("ip") + 2]
            handle = parts[-1]
            nft_rules[ip] = handle

    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM blocked_ips")
        db_ips = set(row[0] for row in cursor.fetchall())
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

    for ip in db_ips - nft_rules.keys():
        logging.info(f"Adding missing nftables rule for IP: {ip}")
        install_nftables_rule(ip)

    for ip in nft_rules.keys() - db_ips:
        logging.info(f"Removing extraneous nftables rule for IP: {ip}")
        remove_nftables_rule_by_handle(nft_rules[ip])

def process_fingerprint_changes():
    """Process fingerprints flagged for addition and add associated IP addresses."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT fingerprint FROM fingerprints WHERE action = 'add' AND timestamp IS NULL")
        additions = cursor.fetchall()

        for (fingerprint,) in additions:
            logging.info(f"Processing addition for fingerprint: {fingerprint}")
            ip_addresses = lookup_ips_for_fingerprint(fingerprint)

            for ip_address in ip_addresses:
                if not is_ip_blocked(ip_address, fingerprint):
                    install_nftables_rule(ip_address)
                    log_blocked_ip(ip_address, fingerprint)

            cursor.execute("UPDATE fingerprints SET timestamp = ? WHERE fingerprint = ? AND action = 'add'", (datetime.now(), fingerprint))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

def process_fingerprint_removals():
    """Process fingerprints flagged for removal and remove associated IP addresses."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT fingerprint FROM fingerprints WHERE action = 'remove'")
        removals = cursor.fetchall()

        for (fingerprint,) in removals:
            logging.info(f"Processing removal for fingerprint: {fingerprint}")
            
            # Remove the fingerprint entry
            cursor.execute("DELETE FROM fingerprints WHERE fingerprint = ?", (fingerprint,))
            conn.commit()

            # Fetch all IP addresses associated with the fingerprint
            cursor.execute("SELECT ip_address FROM blocked_ips WHERE fingerprint = ?", (fingerprint,))
            ip_addresses = cursor.fetchall()

            # Remove all IP addresses associated with the fingerprint
            for (ip_address,) in ip_addresses:
                remove_nftables_rule_by_ip(ip_address)

            # Remove entries from blocked_ips table
            cursor.execute("DELETE FROM blocked_ips WHERE fingerprint = ?", (fingerprint,))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

def lookup_ips_for_fingerprint(fingerprint):
    """Look up IPs associated with a given fingerprint from .part files."""
    ip_addresses = set()
    part_files = glob.glob(os.path.join(PART_FILE_DIRECTORY, "*.part"))

    for part_file_path in part_files:
        with open(part_file_path, "r") as file:
            for line in file:
                try:
                    entry = json.loads(line.strip())
                    if entry.get("muonfp_fingerprint") == fingerprint:
                        ip_addresses.add(entry.get("ip_address"))
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse line in {part_file_path}: {line.strip()}")

    return list(ip_addresses)

def remove_nftables_rule_by_ip(ip_address):
    """Remove nftables rule for a specific IP address."""
    try:
        nft_output = subprocess.run(f"sudo nft -a list ruleset", shell=True, stdout=subprocess.PIPE, text=True, check=True).stdout
        for line in nft_output.splitlines():
            if f"ip saddr {ip_address}" in line:
                try:
                    handle = line.strip().split("handle")[-1].strip()
                    remove_nftables_rule_by_handle(handle)
                    logging.info(f"Removed nftables rule for IP: {ip_address} with handle: {handle}")
                except IndexError:
                    logging.error(f"Failed to parse handle for IP: {ip_address}")
        else:
            logging.warning(f"No nftables rule found for IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to list nftables ruleset: {e}")

def remove_nftables_rule_by_handle(handle):
    """Remove a specific nftables rule using its handle."""
    command = f"sudo nft delete rule inet filter input handle {handle}"
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Removed nftables rule with handle: {handle}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to remove nftables rule with handle: {handle}")
        logging.error(e)

def process_part_files():
    """Process all .part files in the directory to find matching fingerprints and associated IP addresses."""
    part_files = glob.glob(os.path.join(PART_FILE_DIRECTORY, "*.part"))

    if part_files:
        for part_file_path in part_files:
            logging.info(f"Processing file: {part_file_path}")
            with open(part_file_path, "r") as file:
                for line in file:
                    try:
                        entry = json.loads(line.strip())
                        ip_address = entry.get("ip_address")
                        fingerprint = entry.get("muonfp_fingerprint")

                        conn = sqlite3.connect(DATABASE_FILE)
                        try:
                            cursor = conn.cursor()
                            cursor.execute("SELECT 1 FROM fingerprints WHERE fingerprint = ? AND action = 'add'", (fingerprint,))
                            fingerprint_exists = cursor.fetchone()
                        except sqlite3.Error as e:
                            logging.error(f"Database error: {e}")
                        finally:
                            conn.close()

                        if fingerprint_exists and not is_ip_blocked(ip_address, fingerprint):
                            logging.info(f"Found matching fingerprint: {fingerprint} for IP: {ip_address}")
                            install_nftables_rule(ip_address)
                            log_blocked_ip(ip_address, fingerprint)
                    except json.JSONDecodeError:
                        logging.error(f"Failed to parse line: {line.strip()}")
    else:
        logging.warning(f"No .part files found in: {PART_FILE_DIRECTORY}")

def install_nftables_rule(ip_address):
    """Install an nftables rule to drop traffic from the specified IP address."""
    try:
        nft_output = subprocess.run(f"sudo nft list chain inet filter input", shell=True, stdout=subprocess.PIPE, text=True, check=True).stdout
        for line in nft_output.splitlines():
            if f"ip saddr {ip_address}" in line:
                logging.info(f"Rule for IP {ip_address} already exists. Skipping.")
                return

        command = f"sudo nft add rule inet filter input ip saddr {ip_address} counter drop"
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Installed nftables rule to drop traffic from IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install nftables rule for IP: {ip_address}")
        logging.error(e)

def is_ip_blocked(ip_address, fingerprint):
    """Check if an IP address with a specific fingerprint is already blocked."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM blocked_ips WHERE ip_address = ? AND fingerprint = ?", (ip_address, fingerprint))
        result = cursor.fetchone()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        result = None
    finally:
        conn.close()
    return result is not None

def log_blocked_ip(ip_address, fingerprint):
    """Log the blocked IP address, fingerprint, and timestamp in the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip_address, fingerprint, timestamp) VALUES (?, ?, ?)",
                       (ip_address, fingerprint, datetime.now()))
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
    finally:
        conn.close()

def main():
    setup_database()
    reconcile_nftables_with_db()
    while True:
        process_fingerprint_changes()
        process_fingerprint_removals()
        process_part_files()
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    logging.info("Starting fpfwd.py script")
    main()

