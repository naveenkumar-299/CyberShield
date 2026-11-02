"""CyberShield SOC Universal Entry Point.

Supports both:
  1. Standard Flask Web Server:
     python run.py
  2. Streamlit Cloud / Streamlit UI:
     streamlit run run.py (or streamlit run streamlit_app.py)
"""
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Detect if executing under Streamlit Cloud / Streamlit CLI
is_streamlit = False
try:
    import streamlit.runtime
    if streamlit.runtime.exists():
        is_streamlit = True
except Exception:
    pass

if not is_streamlit:
    if any("streamlit" in str(arg).lower() for arg in sys.argv) or os.getenv("STREAMLIT_SERVER_PORT"):
        is_streamlit = True

if is_streamlit:
    # Delegate directly to standalone Streamlit application
    import streamlit_app
    streamlit_app.main()
else:
    # Standard Flask execution
    from app import create_app
    from app.database.init_db import init_database

    app = create_app(os.getenv("FLASK_ENV", "development"))

    if __name__ == "__main__":
        with app.app_context():
            init_database()
        port = int(os.getenv("PORT", 5000))
        host = os.getenv("HOST", "0.0.0.0")
        app.run(host=host, port=port, debug=os.getenv("DEBUG", "False").lower() == "true")
