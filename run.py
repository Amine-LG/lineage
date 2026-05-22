"""Lineage entry point. `python run.py` to start the web UI."""

import os

from lineage.main import app

if __name__ == "__main__":
    host = os.environ.get("LINEAGE_HOST", "127.0.0.1")
    port = int(os.environ.get("LINEAGE_PORT", "8080"))
    debug = os.environ.get("LINEAGE_DEBUG") == "1"
    app.run(host=host, port=port, debug=debug)
