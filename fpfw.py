#!/usr/bin/env python3

import sqlite3
import sys
import subprocess
from datetime import datetime

# Configuration
DATABASE_FILE = "fpfwd.db"  # SQLite database file

def add_fingerprint(fingerprint):
    """Add a fingerprint to the database with the 'add' action."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO fingerprints (fingerprint, action) VALUES (?, ?)", (fingerprint, 'add'))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()
    print(f"Added fingerprint: {fingerprint}")

def remove_fingerprint(fingerprint):
    """Remove a fingerprint from the database and unblock associated IP addresses."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
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
        print(f"Database error: {e}")
    finally:
        conn.close()
    print(f"Removed fingerprint: {fingerprint}")

def remove_nftables_rule_by_ip(ip_address):
    """Remove nftables rule for a specific IP address."""
    try:
        nft_output = subprocess.run(f"sudo nft -a list ruleset", shell=True, stdout=subprocess.PIPE, text=True, check=True).stdout
        for line in nft_output.splitlines():
            if f"ip saddr {ip_address}" in line:
                try:
                    handle = line.strip().split("handle")[-1].strip()
                    remove_nftables_rule_by_handle(handle)
                    print(f"Removed nftables rule for IP: {ip_address} with handle: {handle}")
                except IndexError:
                    print(f"Failed to parse handle for IP: {ip_address}")
        else:
            print(f"No nftables rule found for IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to list nftables ruleset: {e}")

def remove_nftables_rule_by_handle(handle):
    """Remove a specific nftables rule using its handle."""
    command = f"sudo nft delete rule inet filter input handle {handle}"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Removed nftables rule with handle: {handle}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to remove nftables rule with handle: {handle}")
        print(e)

def show_fingerprints():
    """Show all unique fingerprints currently being blocked."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT fingerprint FROM fingerprints WHERE action = 'add' AND timestamp IS NOT NULL")
        fingerprints = cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        fingerprints = []
    finally:
        conn.close()

    if fingerprints:
        print("Fingerprints currently being blocked:")
        for fp in fingerprints:
            print(fp[0])
    else:
        print("No fingerprints are currently being blocked.")

def flush_nftables():
    """Flush all nftables rules and clear the database."""
    try:
        # Flush all rules in the inet filter table
        subprocess.run("sudo nft flush table inet filter", shell=True, check=True)
        print("Flushed all nftables rules in the inet filter table.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to flush nftables rules: {e}")

    # Clear the database
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM fingerprints")
        cursor.execute("DELETE FROM blocked_ips")
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()
    print("Cleared the fpfwd.db database.")

def print_usage():
    """Print the usage statement."""
    print("""
Usage: fpfw <command> [fingerprint]

Commands:
  add <fingerprint>      Add a fingerprint to be blocked.
  remove <fingerprint>   Remove a fingerprint from being blocked.
  show                   Show all unique fingerprints currently being blocked.
  flush                  Flush all nftables rules and clear the fpfwd.db database.
  -h, --help             Show this help message and exit.
""")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "add" and len(sys.argv) == 3:
        fingerprint = sys.argv[2]
        add_fingerprint(fingerprint)
    elif command == "remove" and len(sys.argv) == 3:
        fingerprint = sys.argv[2]
        remove_fingerprint(fingerprint)
    elif command == "show":
        show_fingerprints()
    elif command == "flush":
        flush_nftables()
    else:
        print("Invalid command. Use 'add', 'remove', 'show', 'flush', or '-h' for help.")
        sys.exit(1)

if __name__ == "__main__":
    main()

