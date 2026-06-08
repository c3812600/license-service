import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env BEFORE importing anything else
load_dotenv(Path(__file__).resolve().parent / ".env")

from license_service import create_app

app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT") or "8765")
    app.run(host="0.0.0.0", port=port, debug=False)
