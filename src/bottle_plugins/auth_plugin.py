from bottle import request, abort
import logging
from utils import get_expected_api_key

EXPECTED_API_KEY = get_expected_api_key()

def api_key_auth_plugin(callback):
    """
    Bottle plugin to check for a valid API key in the X-API-Key header.
    """
    def wrapper(*args, **kwargs):
        # Skip auth check for health and root endpoints
        if request.path in ['/health', '/']:
            return callback(*args, **kwargs)
        
        if EXPECTED_API_KEY:
            auth_key = request.headers.get('X-API-Key')
            import secrets
            if auth_key is None or not secrets.compare_digest(auth_key, EXPECTED_API_KEY):
                logging.warning("API key authentication failed. Missing or invalid X-API-Key header.")
                abort(401, "Unauthorized: Invalid or missing API key.")
        
        return callback(*args, **kwargs)
    
    return wrapper
