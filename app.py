import os
from pathlib import Path

from license_service import create_app
from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parent / ".env")

app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT") or "8765")
    app.run(host="0.0.0.0", port=port, debug=False)
