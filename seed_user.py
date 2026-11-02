"""User Password Provisioning and Seeding Script for CyberShield Client Portal.

Allows seeding or updating client passwords:
  1. Interactive mode:
     python seed_user.py

  2. Update all normal users (user01 - user10) with one password:
     python seed_user.py --all --password "UserSecure#123"

  3. Update a single specific user:
     python seed_user.py --username user01 --password "User01Pass#123"

  4. Reset all users to the password configured in .env:
     python seed_user.py --from-env
"""
import os
import sys
import getpass
import argparse
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent


def update_env_user_password(password: str) -> None:
    """Optionally update NORMAL_USER_DEFAULT_PASSWORD in .env."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    found = False
    for line in lines:
        if line.startswith("NORMAL_USER_DEFAULT_PASSWORD=") or line.startswith("#NORMAL_USER_DEFAULT_PASSWORD="):
            new_lines.append(f"NORMAL_USER_DEFAULT_PASSWORD={password}\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"NORMAL_USER_DEFAULT_PASSWORD={password}\n")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def seed_user_passwords(username: str, password: str, update_all: bool = False, update_env: bool = False) -> None:
    """Hash password using Argon2id and update target user(s) in the SQLite database."""
    if not password:
        print("[!] Error: Password cannot be empty.")
        return

    from app import create_app
    from app.extensions import db
    from app.models.user import User
    from app.models.response_action import ResponseAction
    from app.auth.password_service import PasswordService
    from app.database.init_db import init_database

    app = create_app()
    with app.app_context():
        # Ensure database tables and provisioned users exist
        init_database()

        pw_hash = PasswordService.hash_password(password)

        if update_all or username.lower() == "all":
            users = User.query.filter_by(role="user").all()
            if not users:
                print("[!] No normal user accounts found. Running initialization...")
                init_database()
                users = User.query.filter_by(role="user").all()

            for u in users:
                u.password_hash = pw_hash
                u.is_active = True
                u.is_locked = False
                u.locked_until = None
                u.failed_login_attempts = 0

            # Revoke defensive blocks on these users
            user_names = [u.username for u in users]
            ResponseAction.query.filter(
                ResponseAction.target.in_(user_names),
                ResponseAction.status.in_(["APPLIED", "SIMULATED"])
            ).update({"status": "REVOKED", "revoked_by": "seed_user"}, synchronize_session=False)

            db.session.commit()

            if update_env:
                update_env_user_password(password)

            print("\n" + "=" * 65)
            print(" [SUCCESS] All Client Portal User Passwords Seeded Successfully!")
            print("=" * 65)
            print(f"  - Total Accounts Updated : {len(users)} users ({users[0].username} ... {users[-1].username})")
            print(f"  - Password Hash Algorithm : Argon2id (RFC 9106)")
            print(f"  - Account Status          : Unlocked & Active (0 failed attempts)")
            print(f"  - Client Login Portal     : http://127.0.0.1:5000/login")
            print("=" * 65)
            print("\nYou can now log in at http://127.0.0.1:5000/login with:")
            for u in users[:5]:
                print(f"   * Username: {u.username:<10} | Password: [Your new password]")
            if len(users) > 5:
                print(f"   * ... and {len(users) - 5} more users (up to {users[-1].username})")
            print()

        else:
            # Single user update or creation
            target_user = User.query.filter_by(username=username).first()
            if not target_user:
                email = f"{username}@loginguard.local"
                target_user = User(
                    username=username,
                    email=email,
                    password_hash=pw_hash,
                    role="user",
                    is_active=True
                )
                db.session.add(target_user)
                action_text = f"Created new user account '{username}'"
            else:
                target_user.password_hash = pw_hash
                target_user.is_active = True
                target_user.is_locked = False
                target_user.locked_until = None
                target_user.failed_login_attempts = 0
                action_text = f"Updated existing user account '{username}'"

            # Clear blocks on this user
            ResponseAction.query.filter(
                ResponseAction.target == username,
                ResponseAction.status.in_(["APPLIED", "SIMULATED"])
            ).update({"status": "REVOKED", "revoked_by": "seed_user"}, synchronize_session=False)

            db.session.commit()

            print("\n" + "=" * 65)
            print(" [SUCCESS] User Password Successfully Seeded!")
            print("=" * 65)
            print(f"  - Action   : {action_text}")
            print(f"  - Username : {target_user.username}")
            print(f"  - Role     : {target_user.role}")
            print(f"  - Status   : Active, Unlocked (0 failed attempts)")
            print(f"  - Portal   : http://127.0.0.1:5000/login")
            print("=" * 65 + "\n")


def interactive_seed():
    print("\n" + "=" * 65)
    print("   CYBERSHIELD: CLIENT USER PASSWORD SEEDING CONSOLE")
    print("=" * 65)
    print("This utility sets the password for client portal accounts.\n")

    load_dotenv(BASE_DIR / ".env")

    target = input("Target username ('all' for user01-user10, or enter specific username) [all]: ").strip()
    if not target:
        target = "all"

    while True:
        try:
            pwd = getpass.getpass(f"Enter new password for '{target}' (input hidden): ").strip()
        except Exception:
            pwd = input(f"Enter new password for '{target}': ").strip()

        if not pwd:
            print("[!] Password cannot be empty.")
            continue
        if len(pwd) < 6:
            print("[!] Password should be at least 6 characters.")
            continue
        break

    update_all = (target.lower() == "all")
    seed_user_passwords(target, pwd, update_all=update_all, update_env=update_all)


def main():
    parser = argparse.ArgumentParser(description="Seed or update client user passwords in CyberShield.")
    parser.add_argument("--username", "-u", help="Specific username to update (e.g. user01)")
    parser.add_argument("--password", "-p", help="New password for the user(s)")
    parser.add_argument("--all", "-a", action="store_true", help="Apply password to all normal users (user01 through user10)")
    parser.add_argument("--from-env", action="store_true", help="Seed all users using NORMAL_USER_DEFAULT_PASSWORD from .env")
    parser.add_argument("--save-env", action="store_true", help="Save the new password to .env as NORMAL_USER_DEFAULT_PASSWORD")

    args = parser.parse_args()
    load_dotenv(BASE_DIR / ".env")

    if args.from_env:
        pwd = os.getenv("NORMAL_USER_DEFAULT_PASSWORD") or "UserSecure#2026!Passcode"
        print(f"[+] Seeding all users with default password from .env...")
        seed_user_passwords("all", pwd, update_all=True, update_env=False)
        return

    if args.all and args.password:
        seed_user_passwords("all", args.password, update_all=True, update_env=args.save_env)
        return

    if args.username and args.password:
        seed_user_passwords(args.username, args.password, update_all=False)
        return

    # If run without CLI arguments, run interactive console
    interactive_seed()


if __name__ == "__main__":
    main()
