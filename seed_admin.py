#!/usr/bin/env python
"""Seed Administrator Account for CyberShield-SOC.

Usage Examples:
  # 1. Interactive prompt (asks for username, email, and password):
  python seed_admin.py

  # 2. Seed directly from .env variables:
  python seed_admin.py --from-env

  # 3. Direct command-line specification:
  python seed_admin.py --username admin --password "YourStrongPassword#2026" --email "admin@example.com"
"""
import setup_admin

if __name__ == "__main__":
    setup_admin.main()
