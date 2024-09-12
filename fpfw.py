#!/usr/bin/env python3

import sqlite3
import sys
import subprocess
import os

# Configuration
DATABASE_FILE = "/home/admin/muonfp/fpfw/fpfwd.db"  # SQLite database file

def check_sudo():
    """Check if the script is run with sudo privileges."""
    if os.geteuid() != 0:
        print("This script must be run with sudo privileges.")
        sys.exit(1)

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
        nft_output = subprocess.run(f"nft -a list ruleset", shell=True, stdout=subprocess.PIPE, text=True, check=True).stdout
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
    command = f"nft delete rule inet filter input handle {handle}"
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Removed nftables rule with handle: {handle}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to remove nftables rule with handle: {handle}")
        print(e)

def install_nftables_rule(ip_address):
    """Install an nftables rule to drop traffic from the specified IP address."""
    try:
        nft_output = subprocess.run(f"nft list chain inet filter input", shell=True, stdout=subprocess.PIPE, text=True, check=True).stdout
        for line in nft_output.splitlines():
            if f"ip saddr {ip_address}" in line:
                print(f"Rule for IP {ip_address} already exists. Skipping.")
                return

        command = f"nft add rule inet filter input ip saddr {ip_address} counter drop"
        subprocess.run(command, shell=True, check=True)
        print(f"Installed nftables rule to drop traffic from IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install nftables rule for IP: {ip_address}")
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
        # Check if the inet filter table exists
        check_command = "nft list tables | grep 'table inet filter'"
        subprocess.run(check_command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # If the check passes, flush the table
        subprocess.run("nft flush table inet filter", shell=True, check=True)
        print("Flushed all nftables rules in the inet filter table.")
    except subprocess.CalledProcessError:
        print("The inet filter table does not exist or cannot be accessed.")

    # Clear the database
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM fingerprints")
        cursor.execute("DELETE FROM blocked_ips")
        conn.commit()
        print("Cleared the fpfwd.db database.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def resync_nftables_with_db():
    """Resynchronize nftables rules with the SQLite database."""
    conn = sqlite3.connect(DATABASE_FILE)
    try:
        cursor = conn.cursor()

        # Get all active fingerprints from the fingerprints table
        cursor.execute("SELECT DISTINCT fingerprint FROM fingerprints WHERE action = 'add'")
        active_fingerprints = set(row[0] for row in cursor.fetchall())

        # Get all IP addresses that should be blocked based on active fingerprints
        cursor.execute("SELECT ip_address, fingerprint FROM blocked_ips WHERE fingerprint IN ({})".format(
            ','.join('?' for _ in active_fingerprints)), tuple(active_fingerprints))
        should_be_blocked = {row[0]: row[1] for row in cursor.fetchall()}

        # Get current nftables rules
        try:
            nft_output = subprocess.run("nft list ruleset", shell=True, check=True, capture_output=True, text=True).stdout
            current_blocked_ips = set()
            for line in nft_output.splitlines():
                if "ip saddr" in line and "counter drop" in line:
                    ip = line.split()[7]
                    current_blocked_ips.add(ip)
        except subprocess.CalledProcessError:
            print("Failed to get current nftables rules.")
            return

        # Remove rules for IPs that shouldn't be blocked
        for ip in current_blocked_ips - set(should_be_blocked.keys()):
            remove_nftables_rule_by_ip(ip)
            print(f"Removed nftables rule for IP: {ip}")

        # Add rules for IPs that should be blocked but aren't
        for ip in set(should_be_blocked.keys()) - current_blocked_ips:
            install_nftables_rule(ip)
            print(f"Added nftables rule for IP: {ip}")

        # Remove IPs from blocked_ips table if their fingerprint is not active
        cursor.execute("DELETE FROM blocked_ips WHERE fingerprint NOT IN ({})".format(
            ','.join('?' for _ in active_fingerprints)), tuple(active_fingerprints))
        removed_count = cursor.rowcount
        conn.commit()
        print(f"Removed {removed_count} IP(s) from blocked_ips table due to inactive fingerprints.")

        print("Resynchronization completed.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def print_usage():
    """Print the usage statement."""
    print("""
Usage: sudo fpfw <command> [fingerprint]

Commands:
  add <fingerprint>      Add a fingerprint to be blocked.
  remove <fingerprint>   Remove a fingerprint from being blocked.
  show                   Show all unique fingerprints currently being blocked.
  flush                  Flush all nftables rules and clear the fpfwd.db database.
  resync                 Resynchronize nftables rules with the database.
  -h, --help             Show this help message and exit.
""")

def main():
    check_sudo()  # Check for sudo privileges at the start

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    # Check database permissions
    if not os.access(DATABASE_FILE, os.W_OK):
        print(f"Error: No write permission for the database file: {DATABASE_FILE}")
        sys.exit(1)

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
    elif command == "resync":
        resync_nftables_with_db()
    else:
        print("Invalid command. Use 'add', 'remove', 'show', 'flush', 'resync', or '-h' for help.")
        sys.exit(1)

if __name__ == "__main__":
    main()
