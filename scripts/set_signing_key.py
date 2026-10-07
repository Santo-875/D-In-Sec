import os
import sys
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from m3.crypto_signer import generate_rsa_key_pair

priv, pub = generate_rsa_key_pair()
escaped = priv.replace('\n', '\\n')

env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
with open(env_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove any multi-line private keys in comments or variables
content = re.sub(r'# M3_SIGNING_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\r?\n[\s\S]*?-----END PRIVATE KEY-----\r?\n"', '', content)
content = re.sub(r'M3_SIGNING_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\r?\n[\s\S]*?-----END PRIVATE KEY-----\r?\n"', '', content)
content = re.sub(r'M3_SIGNING_PRIVATE_KEY=.*', '', content)

content = content.strip() + f'\n\nM3_SIGNING_PRIVATE_KEY="{escaped}"\n'

with open(env_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Successfully generated and saved clean M3_SIGNING_PRIVATE_KEY to .env!")
