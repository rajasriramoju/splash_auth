import logging
import os

logger = logging.getLogger("splash_auth.config")


JWT_SECRET = os.environ["JWT_SECRET"]
TOKEN_EXP_TIME = int(os.environ["TOKEN_EXP_TIME"])
OAUTH_AUTH_ENDPOINT = os.environ["OAUTH_AUTH_ENDPOINT"]
OAUTH_CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]
OAUTH_CLIENT_SECRET = os.environ["OAUTH_CLIENT_SECRET"]
OAUTH_REDIRECT_URI = os.environ["OAUTH_REDIRECT_URI"]
OAUTH_TOKEN_URI = os.environ[
    "OAUTH_TOKEN_URI"
]  # can be found at https://accounts.google.com/.well-known/openid-configuration
OUATH_SUCCESS_REDIRECT_URI = os.environ["OUATH_SUCCESS_REDIRECT_URI"]
OUATH_FAIL_REDIRECT_URI = os.environ["OUATH_FAIL_REDIRECT_URI"]
OUATH_JWKS_URI = os.environ["OUATH_JWKS_URI"]
HTTP_CLIENT_MAX_CONNECTIONS = int(os.getenv("HTTP_CLIENT_MAX_CONNECTIONS", 100))
HTTP_CLIENT_TIMEOUT_ALL = float(os.getenv("HTTP_CLIENT_TIMEOUT_ALL", 5.0))
HTTP_CLIENT_TIMEOUT_CONNECT = float(os.getenv("HTTP_CLIENT_TIMEOUT_CONNECT", 3.0))
HTTP_CLIENT_TIMEOUT_POOL = int(os.getenv("HTTP_CLIENT_TIMEOUT_POOL", 10))


google_claims = {
    "iss": "https://accounts.google.com",
    "azp": OAUTH_CLIENT_ID,
    "aud": OAUTH_CLIENT_ID,
}

logger.info(f"JWT_SECRET {JWT_SECRET}")
logger.info(f"TOKEN_EXP_TIME {TOKEN_EXP_TIME}")
logger.info(f"OAUTH_AUTH_ENDPOINT {OAUTH_AUTH_ENDPOINT}")
logger.info(f"OAUTH_CLIENT_ID {OAUTH_CLIENT_ID}")
logger.info("OAUTH_CLIENT_SECRET is a secret")
logger.info(f"OAUTH_REDIRECT_URI {OAUTH_REDIRECT_URI}")
logger.info(f"OAUTH_TOKEN_URI {OAUTH_TOKEN_URI}")
logger.info(f"OUATH_SUCCESS_REDIRECT_URI {OUATH_SUCCESS_REDIRECT_URI}")
logger.info(f"OUATH_FAIL_REDIRECT_URI {OUATH_FAIL_REDIRECT_URI}")
logger.info(f"OUATH_JWKS_URI {OUATH_JWKS_URI}")
logger.info(f"HTTP_CLIENT_MAX_CONNECTIONS  {HTTP_CLIENT_MAX_CONNECTIONS}")
logger.info(f"HTTP_CLIENT_TIMEOUT_ALL  {HTTP_CLIENT_TIMEOUT_ALL}")
logger.info(f"HTTP_CLIENT_TIMEOUT_CONNECT  {HTTP_CLIENT_TIMEOUT_CONNECT}")
logger.info(f"HTTP_CLIENT_TIMEOUT_POOL  {HTTP_CLIENT_TIMEOUT_POOL}")


class Config:
    jwt_secret = JWT_SECRET
    token_exp_time = TOKEN_EXP_TIME
    oauth_endpoint = OAUTH_AUTH_ENDPOINT
    oauth_client_id = OAUTH_CLIENT_ID
    oauth_client_secret = OAUTH_CLIENT_SECRET
    oauth_redirect_uri = OAUTH_REDIRECT_URI
    oauth_token_url = OAUTH_TOKEN_URI
    oauth_success_redirect_uri = OUATH_SUCCESS_REDIRECT_URI
    oauth_fail_redirect_uri = OUATH_FAIL_REDIRECT_URI
    oauth_jwks_uri = OUATH_JWKS_URI

    http_client_max_connections = HTTP_CLIENT_MAX_CONNECTIONS
    http_client_timeout_all = HTTP_CLIENT_TIMEOUT_ALL
    http_client_timeout_connect = HTTP_CLIENT_TIMEOUT_CONNECT
    http_client_timeout_pool = HTTP_CLIENT_TIMEOUT_POOL


config = Config()
