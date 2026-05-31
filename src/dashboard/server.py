import os
import sys
import time
import webbrowser
import threading
from pathlib import Path

# Add project root to sys.path to allow importing from src
root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import uvicorn

def open_browser():
    """Open the browser after a short delay to allow uvicorn to start."""
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8501")

def main():
    # Start browser opener thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run uvicorn server
    # host is 127.0.0.1 for local security, port matches streamlit 8501
    print("Starting ThreatLens AI SOC Dashboard Server...")
    print("Access the dashboard at http://127.0.0.1:8501")
    uvicorn.run("src.dashboard.api:app", host="127.0.0.1", port=8501, reload=True)

if __name__ == "__main__":
    main()
