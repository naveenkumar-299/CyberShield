"""LoginGuard-SOC Entry Point."""
import os
from app import create_app
from app.database.init_db import init_database

app = create_app(os.getenv("FLASK_ENV", "development"))

if __name__ == "__main__":
    with app.app_context():
        # Ensure database and provisioned accounts exist
        init_database()
    # Run development server
    port = int(os.getenv("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
