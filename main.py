"""
main.py — VaultX Command-Line Interface
----------------------------------------
Run with:  python main.py
"""

import getpass
import sys
from vault import (
    initialise_vault, unlock_vault,
    add_entry, get_entry, list_sites, delete_entry,
    load_vault,
)


BANNER = """
╔══════════════════════════════╗
║   VaultX — Password Vault   ║
║   AES-256 · PBKDF2-SHA256   ║
╚══════════════════════════════╝
"""

MENU = """
  [1] Add credential
  [2] Retrieve credential
  [3] List all sites
  [4] Delete credential
  [5] Exit
"""


def prompt_master_password(confirm: bool = False) -> str:
    """Prompt for master password without echoing it to the terminal."""
    pw = getpass.getpass("  Master password: ")
    if confirm:
        pw2 = getpass.getpass("  Confirm master password: ")
        if pw != pw2:
            print("  ✗ Passwords do not match.")
            sys.exit(1)
    return pw


def main():
    print(BANNER)

    vault = load_vault()
    is_new = vault["salt"] is None

    if is_new:
        print("  No vault found — creating a new one.\n")
        master = prompt_master_password(confirm=True)
        key = initialise_vault(master)
        print("  ✓ Vault created successfully.\n")
    else:
        print("  Vault found. Enter your master password to unlock.\n")
        master = prompt_master_password()
        try:
            key = unlock_vault(master)
            print("  ✓ Vault unlocked.\n")
        except Exception:
            print("  ✗ Could not unlock vault.")
            sys.exit(1)

    while True:
        print(MENU)
        choice = input("  Choice: ").strip()

        if choice == "1":
            site = input("  Site/App name: ").strip()
            username = input("  Username/Email: ").strip()
            password = getpass.getpass("  Password: ")
            add_entry(site, username, password, key)
            print(f"  ✓ Credentials for '{site}' saved.\n")

        elif choice == "2":
            site = input("  Site/App name: ").strip()
            result = get_entry(site, key)
            if result:
                print(f"\n  Site:     {result['site']}")
                print(f"  Username: {result['username']}")
                print(f"  Password: {result['password']}\n")
            else:
                print(f"  ✗ No entry found for '{site}'.\n")

        elif choice == "3":
            sites = list_sites()
            if sites:
                print("\n  Stored sites:")
                for s in sites:
                    print(f"    · {s}")
                print()
            else:
                print("  No credentials stored yet.\n")

        elif choice == "4":
            site = input("  Site to delete: ").strip()
            if delete_entry(site):
                print(f"  ✓ '{site}' deleted.\n")
            else:
                print(f"  ✗ '{site}' not found.\n")

        elif choice == "5":
            print("  Goodbye.\n")
            break

        else:
            print("  Invalid choice. Try again.\n")


if __name__ == "__main__":
    main()
