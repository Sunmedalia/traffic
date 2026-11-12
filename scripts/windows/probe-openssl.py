"""Windows OpenSSL helper. Keep probe-iis.py and openssl-plaintext.js alongside this file."""
import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.argv.extend(["--backend", "openssl"])
    runpy.run_path(str(Path(__file__).with_name("probe-iis.py")), run_name="__main__")
