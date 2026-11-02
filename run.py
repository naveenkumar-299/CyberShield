"""LoginGuard-SOC Entry Point.

Supports both:
  1. Standard Flask execution:
     python run.py
  2. Streamlit Cloud / Streamlit UI execution:
     streamlit run run.py  (or streamlit run streamlit_app.py)
"""
import os
import sys
from pathlib import Path

# Add project root to sys.path so modules like `app` and `config` are always found
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Check if launched inside Streamlit execution environment
is_streamlit = False
try:
    import streamlit.runtime
    if streamlit.runtime.exists():
        is_streamlit = True
except Exception:
    pass

if is_streamlit:
    # Delegate seamlessly to Streamlit SOC dashboard
    import streamlit_app
    streamlit_app.main()
else:
    # Standard Flask WSGI execution
    from app import create_app
    from app.database.init_db import init_database

    app = create_app(os.getenv("FLASK_ENV", "development"))

    if __name__ == "__main__":
        with app.app_context():
            # Ensure database and provisioned accounts exist
            init_database()
        port = int(os.getenv("PORT", 5000))
        host = os.getenv("HOST", "0.0.0.0")
        app.run(host=host, port=port, debug=os.getenv("DEBUG", "False").lower() == "true")
