"""
vault/service.py — Public-facing Vault API.
This is the ONLY file that routes/app.py should import from the vault.
No other file should ever import crypto.py or token_manager.py directly.
"""

import logging
from vault.token_manager import store, retrieve, update, VaultAccessError

logger = logging.getLogger('mock_site')


def vault_store_profile(user_id: int, profile_data: dict) -> str:
    """
    Encrypt and store a user's profile PII in the vault.
    Returns the profile_token to be saved in the main DB.
    """
    token_id = store(owner_id=user_id, purpose='profile', data=profile_data)
    logger.info(f"event=VAULT_STORE purpose=profile actor_id={user_id} token={token_id[:8]}...")
    return token_id


def vault_get_profile(token_id: str, requesting_user_id: int) -> dict:
    """
    Retrieve and decrypt a user's profile from the vault.
    Returns the profile dict, or empty dict on failure.
    """
    if not token_id:
        return {}
    try:
        data = retrieve(token_id, requesting_user_id)
        logger.info(f"event=VAULT_ACCESS purpose=profile actor_id={requesting_user_id} token={token_id[:8]}... status=success")
        return data
    except VaultAccessError as e:
        logger.warning(f"event=VAULT_FAIL purpose=profile actor_id={requesting_user_id} token={token_id[:8]}... reason={e}")
        return {}


def vault_update_profile(token_id: str, user_id: int, profile_data: dict):
    """
    Re-encrypt updated profile data into an existing token.
    """
    try:
        update(token_id, user_id, profile_data)
        logger.info(f"event=VAULT_UPDATE purpose=profile actor_id={user_id} token={token_id[:8]}... status=success")
    except VaultAccessError as e:
        logger.warning(f"event=VAULT_FAIL purpose=profile_update actor_id={user_id} reason={e}")
        raise


def vault_store_file(user_id: int, file_bytes: bytes, meta: dict) -> str:
    """
    Encrypt and store a file's raw bytes + metadata in the vault.
    Returns the file_token to be saved in the main DB.
    """
    data = {'meta': meta, 'file_b64': file_bytes.hex()}
    token_id = store(owner_id=user_id, purpose='document', data=data)
    logger.info(f"event=VAULT_STORE purpose=document actor_id={user_id} token={token_id[:8]}...")
    return token_id


def vault_get_file(token_id: str, requesting_user_id: int):
    """
    Retrieve and decrypt a stored file from the vault.
    Returns (file_bytes, meta_dict), or (None, None) on failure.
    """
    try:
        data = retrieve(token_id, requesting_user_id)
        file_bytes = bytes.fromhex(data['file_b64'])
        meta = data['meta']
        logger.info(f"event=VAULT_ACCESS purpose=document actor_id={requesting_user_id} token={token_id[:8]}... status=success")
        return file_bytes, meta
    except VaultAccessError as e:
        logger.warning(f"event=VAULT_FAIL purpose=document actor_id={requesting_user_id} token={token_id[:8]}... reason={e}")
        return None, None
