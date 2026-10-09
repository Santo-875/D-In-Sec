import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from m3.crypto_signer import generate_rsa_key_pair

if __name__ == "__main__":
    priv, _ = generate_rsa_key_pair()
    escaped = priv.strip().replace("\n", "\\n")
    print(escaped)
