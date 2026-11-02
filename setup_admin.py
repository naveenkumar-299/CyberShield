"""Administrator Provisioning and Seeding Script for CyberShield-SOC.

Can be run:
  1. Interactively:
     python seed_admin.py
  2. Directly from CLI arguments:
     python seed_admin.py --username admin --password "MySecretPass123" --email "admin@example.com"
  3. Direct seed from .env settings:
     python seed_admin.py --from-env
"""
import os
import sys
import getpass
import argparse
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

def update_env_file(username: str, email: str, password: str) -> None:
    """Persist administrator credentials to .env so the system remembers them."""
    env_path = BASE_DIR / ".env"
    lines = []
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    keys_to_set = {
        "ADMIN_INITIAL_USERNAME": username,
        "AUTHORIZED_USERNAME": username,
        "ADMIN_INITIAL_EMAIL": email,
        "ADMIN_NOTIFICATION_EMAIL": email,
        "OTP_EMAIL": email,
        "ADMIN_INITIAL_PASSWORD": password,
    }

    found_keys = set()
    new_lines = []

    for line in lines:
        matched = False
        for key, val in keys_to_set.items():
            if line.startswith(f"{key}=") or line.startswith(f"#{key}="):
                new_lines.append(f"{key}={val}\n")
                found_keys.add(key)
                matched = True
                break
        if not matched:
            new_lines.append(line)

    # Append any keys that weren't already in .env
    for key, val in keys_to_set.items():
        if key not in found_keys:
            new_lines.append(f"{key}={val}\n")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def seed_admin_account(username: str, email: str, password: str, persist_to_env: bool = True) -> bool:
    """Hash password with Argon2id and write administrator to SQLite database."""
    if not username or not password:
        print("[!] Error: Username and password cannot be empty.")
        return False

    if persist_to_env:
        update_env_file(username, email, password)
        print("[+] Credentials synchronized to .env.")

    from app import create_app
    from app.extensions import db
    from app.models.user import User
    from app.models.response_action import ResponseAction
    from app.auth.password_service import PasswordService
    from app.database.init_db import init_database

    app = create_app()
    with app.app_context():
        # Ensure schema and base users exist
        init_database()

        # Update or create administrator user
        admin = User.query.filter_by(role="admin").first()
        if not admin:
            admin = User.query.filter_by(username=username).first()

        pw_hash = PasswordService.hash_password(password)
        if admin:
            admin.username = username
            admin.email = email
            admin.password_hash = pw_hash
            admin.role = "admin"
            admin.is_active = True
            admin.is_locked = False
            admin.failed_login_attempts = 0
            action_desc = "Updated existing administrator account"
        else:
            admin = User(
                username=username,
                email=email,
                password_hash=pw_hash,
                role="admin",
                is_active=True
            )
            db.session.add(admin)
            action_desc = "Created new administrator account"

        # Revoke any accidental locks or defensive blocks on this user
        ResponseAction.query.filter(
            ResponseAction.target.in_([username, "127.0.0.1"]),
            ResponseAction.status.in_(["APPLIED", "SIMULATED"])
        ).update({"status": "REVOKED", "revoked_by": "seed_admin"}, synchronize_session=False)

        db.session.commit()

    print("\n" + "=" * 65)
    print(" [SUCCESS] Administrator Account Successfully Seeded & Ready!")
    print("=" * 65)
    print(f"  - Status   : {action_desc}")
    print(f"  - Username : {username}")
    print(f"  - Email    : {email}")
    print(f"  - Password : [SECURED VIA ARGON2id]")
    print(f"  - Role     : SOC Administrator (role='admin')")
    print(f"  - Unlocked : Account active, 0 failed attempts")
    print(f"  - Portal   : http://127.0.0.1:5000/admin/login")
    print("=" * 65 + "\n")
    return True


def setup_admin_interactive():
    print("\n" + "=" * 65)
    print("   CYBERSHIELD-SOC: ADMINISTRATOR CREDENTIAL SETUP CONSOLE")
    print("=" * 65)
    print("This utility configures and seeds your SOC Administrator account.\n")

    load_dotenv(BASE_DIR / ".env")

    curr_user = os.getenv("AUTHORIZED_USERNAME") or os.getenv("ADMIN_INITIAL_USERNAME") or "Naveen"
    curr_email = os.getenv("OTP_EMAIL") or os.getenv("ADMIN_INITIAL_EMAIL") or "naveenlenin29@gmail.com"

    # 1. Prompt Username
    prompt_user = input(f"Enter SOC Administrator Username [{curr_user}]: ").strip()
    admin_username = prompt_user if prompt_user else curr_user

    # 2. Prompt Email
    prompt_email = input(f"Enter Administrator Alert Email [{curr_email}]: ").strip()
    admin_email = prompt_email if prompt_email else curr_email

    # 3. Prompt Password
    while True:
        try:
            admin_pass = getpass.getpass("Enter SOC Administrator Password (input hidden): ").strip()
        except Exception:
            admin_pass = input("Enter SOC Administrator Password: ").strip()

        if not admin_pass:
            print("[!] Password cannot be empty. Please enter a secure passphrase.")
            continue
        if len(admin_pass) < 6:
            print("[!] Password should be at least 6 characters.")
            continue
        break

    seed_admin_account(admin_username, admin_email, admin_pass, persist_to_env=True)


def main():
    parser = argparse.ArgumentParser(
        description="Seed or update the CyberShield SOC Administrator credentials."
    )
    parser.add_argument(
        "--username", "-u",
        help="Administrator username"
    )
    parser.add_argument(
        "--password", "-p",
        help="Administrator password"
    )
    parser.add_argument(
        "--email", "-e",
        help="Administrator alert email address"
    )
    parser.add_argument(
        "--from-env",
        action="store_true",
        help="Seed credentials directly from .env variables without interactive prompt"
    )
    parser.add_argument(
        "--no-save-env",
        action="store_true",
        help="Do not write updated credentials back to .env file"
    )

    args = parser.parse_args()

    load_dotenv(BASE_DIR / ".env")

    if args.from_env:
        username = os.getenv("ADMIN_INITIAL_USERNAME") or os.getenv("AUTHORIZED_USERNAME") or "Naveen"
        email = os.getenv("ADMIN_INITIAL_EMAIL") or os.getenv("OTP_EMAIL") or "naveenlenin29@gmail.com"
        password = os.getenv("ADMIN_INITIAL_PASSWORD") or "Naveen@12345"
        print(f"[+] Seeding admin credentials from .env for user '{username}'...")
        seed_admin_account(username, email, password, persist_to_env=False)
        return

    if args.username and args.password:
        email = args.email or os.getenv("ADMIN_INITIAL_EMAIL") or "naveenlenin29@gmail.com"
        seed_admin_account(args.username, email, args.password, persist_to_env=not args.no_save_env)
        return

    # If no flags provided or only partial flags, run interactive setup
    setup_admin_interactive()


if __name__ == "__main__":
    main()
