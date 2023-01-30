import os

google_claims =  {'iss': 'https://accounts.google.com',
                  'azp': '78908852817-cgqo107ieek019bkr5sd9ohm7avv7cht.apps.googleusercontent.com',
                  'aud': '78908852817-cgqo107ieek019bkr5sd9ohm7avv7cht.apps.googleusercontent.com'
}

JWT_SECRET = os.environ["JWT_SECRET"]
TOKEN_TIME = int(os.environ["TOKEN_EXP_TIME"])
OAUTH_AUTH_ENDPOINT=os.environ["OAUTH_AUTH_ENDPOINT"]
OAUTH_CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]
OAUTH_CLIENT_SECRET = os.environ["OAUTH_CLIENT_SECRET"]
OAUTH_REDIRECT_URI = os.environ["OAUTH_REDIRECT_URI"]
OAUTH_TOKEN_URI = os.environ["OAUTH_TOKEN_URI"] # can be found at https://accounts.google.com/.well-known/openid-configuration
OUATH_SUCCESS_REDIRECT_URI = os.environ["OUATH_SUCCESS_REDIRECT_URI"]
OUATH_FAIL_REDIRECT_URI = os.environ["OUATH_FAIL_REDIRECT_URI"]
OUATH_JWKS_URI = os.environ["OUATH_JWKS_URI"]

print(f"JWT_SECRET {JWT_SECRET}")
print(f"TOKEN_TIME {TOKEN_TIME}")
print(f"OAUTH_AUTH_ENDPOINT {OAUTH_AUTH_ENDPOINT}")
print(f"OAUTH_CLIENT_ID {OAUTH_CLIENT_ID}")
print(f"OAUTH_CLIENT_SECRET {OAUTH_CLIENT_SECRET}")
print(f"OAUTH_REDIRECT_URI {OAUTH_REDIRECT_URI}")
print(f"OAUTH_TOKEN_URI {OAUTH_TOKEN_URI}")
print(f"OUATH_SUCCESS_REDIRECT_URI {OUATH_SUCCESS_REDIRECT_URI}")
print(f"OUATH_FAIL_REDIRECT_URI {OUATH_FAIL_REDIRECT_URI}")
print(f"OUATH_JWKS_URI {OUATH_JWKS_URI}")

class Config():
    jwt_secret = JWT_SECRET
    token_time = TOKEN_TIME
    oauth_endpoint = OAUTH_AUTH_ENDPOINT
    oauth_client_id = OAUTH_CLIENT_ID
    oauth_client_secret = OAUTH_CLIENT_SECRET
    oauth_redirect_uri = OAUTH_REDIRECT_URI
    oauth_token_url = OAUTH_TOKEN_URI
    oauth_success_redirect_uri = OUATH_SUCCESS_REDIRECT_URI
    oauth_fail_redirect_uri = OUATH_FAIL_REDIRECT_URI
    oauth_jwks_uri = OUATH_JWKS_URI

config = Config()