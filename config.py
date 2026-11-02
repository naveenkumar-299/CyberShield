import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the application
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env if present
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)


def _normalize_database_uri(raw_uri: str, base_dir: Path) -> str:
    """Ensure SQLite database URIs are absolute cross-platform paths."""
    if not raw_uri:
        inst = base_dir / "instance"
        inst.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{ (inst / 'loginguard.db').resolve().as_posix() }"

    if raw_uri.startswith("sqlite:///:memory:"):
        return raw_uri

    if raw_uri.startswith("sqlite:///"):
        path_str = raw_uri[len("sqlite:///"):]
        p = Path(path_str)
        if not p.is_absolute():
            resolved = (base_dir / p).resolve()
            resolved.parent.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{resolved.as_posix()}"
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{p.resolve().as_posix()}"

    return raw_uri


def _normalize_file_path(path_str: str, base_dir: Path) -> str:
    """Ensure file paths are absolute cross-platform paths."""
    p = Path(path_str)
    if not p.is_absolute():
        return str((base_dir / p).resolve())
    return str(p.resolve())


class Config:
    """Base application configuration."""

    # Security Secret Key
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)

    # Database
    INSTANCE_DIR = BASE_DIR / "instance"
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = _normalize_database_uri(
        os.getenv("DATABASE_URL", f"sqlite:///{ (INSTANCE_DIR / 'loginguard.db').resolve().as_posix() }"),
        BASE_DIR
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session & Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "yes")
    PERMANENT_SESSION_LIFETIME = int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "30")) * 60

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Rate Limiting
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    RATE_LIMIT_LOGIN = os.getenv("RATE_LIMIT_LOGIN", "10 per minute")
    RATE_LIMIT_MFA = os.getenv("RATE_LIMIT_MFA", "5 per minute")

    # Provisioning & Credentials
    ADMIN_INITIAL_USERNAME = os.getenv("AUTHORIZED_USERNAME") or os.getenv("ADMIN_INITIAL_USERNAME", "analyst")
    ADMIN_INITIAL_EMAIL = os.getenv("OTP_EMAIL") or os.getenv("ADMIN_INITIAL_EMAIL", "naveenlenin29@gmail.com")
    ADMIN_INITIAL_PASSWORD = os.getenv("ADMIN_INITIAL_PASSWORD", "AdminSecure#2026!Passphrase")
    ADMIN_NOTIFICATION_EMAIL = os.getenv("OTP_EMAIL") or os.getenv("ADMIN_NOTIFICATION_EMAIL", "naveenlenin29@gmail.com")
    NORMAL_USER_DEFAULT_PASSWORD = os.getenv("NORMAL_USER_DEFAULT_PASSWORD", "UserSecure#2026!Passcode")

    # MFA Policy
    MFA_EXPIRY_SECONDS = int(os.getenv("MFA_EXPIRY_SECONDS", "300"))
    MFA_MAX_ATTEMPTS = int(os.getenv("MFA_MAX_ATTEMPTS", "3"))
    MFA_RESEND_COOLDOWN_SECONDS = int(os.getenv("MFA_RESEND_COOLDOWN_SECONDS", "60"))
    MFA_CONSECUTIVE_FAILURE_TRIGGER = int(os.getenv("MFA_CONSECUTIVE_FAILURE_TRIGGER", "3"))

    # SMTP Configuration
    SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "True").lower() in ("true", "1", "yes")
    SMTP_SENDER_EMAIL = os.getenv("SMTP_SENDER_EMAIL", "alerts@loginguard.local")

    # IPS Defensive Response Controls
    IPS_DRY_RUN = os.getenv("IPS_DRY_RUN", "True").lower() in ("true", "1", "yes")
    IPS_DEFAULT_BAN_DURATION_SECONDS = int(os.getenv("IPS_DEFAULT_BAN_DURATION_SECONDS", "900"))

    # Suricata EVE IDS Ingestion
    SURICATA_EVE_PATH = _normalize_file_path(
        os.getenv("SURICATA_EVE_PATH", "data/sample_events.json"),
        BASE_DIR
    )
    SURICATA_LIVE_MONITOR = os.getenv("SURICATA_LIVE_MONITOR", "False").lower() in ("true", "1", "yes")

    # Logging Directory
    LOGS_DIR = BASE_DIR / "logs"
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing configuration with in-memory database and test credentials."""
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    ADMIN_INITIAL_USERNAME = "admin_soc"
    ADMIN_INITIAL_EMAIL = "admin.soc@loginguard.local"
    ADMIN_INITIAL_PASSWORD = "AdminSecure#2026!Passphrase"
    ADMIN_NOTIFICATION_EMAIL = "admin.soc@loginguard.local"
    MFA_EXPIRY_SECONDS = 300
    MFA_MAX_ATTEMPTS = 3
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production configuration enforcing HTTPS session cookie."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
