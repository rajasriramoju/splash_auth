import logging
import os
from enum import Enum
from typing import List, Optional, Union

import httpx
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer
from jose import jwt
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse
from starlette.status import HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED

from .config import config
from .oidc import oidc_router
from .user_db import users_db

logger = logging.getLogger("api_auth")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
app = FastAPI()
app.include_router(oidc_router)

ALS_TOKEN_NAME = "als_token"

http_bearer = HTTPBearer(auto_error=False)

AUTH_SITE = """
<html>
    <head>
    <script src="https://code.jquery.com/jquery-2.2.4.js"></script>

    <script>

        var clientId = "264976187249-1k24kq078kum26egec367vvrpuvd2f6d.apps.googleusercontent.com";


        $(document).ready(function() {{
            $("#login").attr("href","{}?response_type=code&redirect_uri={}&client_id={}&scope=openid+email&nonce=foobareddddddddf");
        }});
    </script>
    </head>

    <body>
        <a id="login">Sign into Google</a>
        <h3 id="info"></h3><p id="contents"></p>
    </body>
</html>
"""


def new_httpx_client():
    limits = httpx.Limits(max_connections=config.http_client_max_connections)
    timeout = httpx.Timeout(
        config.http_client_timeout_all,
        connect=config.http_client_timeout_connect,
        pool=config.http_client_timeout_pool,
    )

    return httpx.AsyncClient(
        base_url="http://prefect_server:4200", limits=limits, timeout=timeout
    )


client = new_httpx_client()


@app.on_event("shutdown")
async def shutdown_event():
    global client
    await client.aclose()


class Scopes(str, Enum):
    GET = "get"
    POsT = "post"


@app.get("/login", response_class=HTMLResponse)
async def endpoint_login(redirect: Union[str, None] = None):
    """
    This endpoint prints a login form. Currently, this directs the user to google for login.
    The mechanics of OIDC login from google are handled in oidc.py
    """
    return AUTH_SITE.format(
        config.oauth_endpoint, config.oauth_redirect_uri, config.oauth_client_id
    )
    # return RedirectResponse("http://noether.lbl.gov:7443/data_workspace/login")


@app.api_route(
    "/{path:path}", methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS", "HEAD"]
)
def endpoint_reverse_proxy(
    request: Request,
    response: Response,
    als_token: Union[str, None] = Cookie(default=None),
    # api_key: APIKey = Depends(get_api_key_from_request),
    bearer: HTTPBearer = Depends(http_bearer),
) -> StreamingResponse:
    """
    This endpoint server as a reverse proxy for prefect messages. It authenticates every message using one of
    two methods.

    1. Authorization: Bearer <api_key>
        This method is allows clients to send a provided key. It is the primary way that prefect agents
        can authenticate.

    2. Cookie
        This method is used for logging into the prefect UI. If a cookie is not set in the message, the
        user is redirected to the /login endpoint, which allows them to login.

    """
    logger.info(f"{request.method} - {request.url}")
    # check for api key in bearer
    if bearer:
        if bearer.credentials in users_db.api_keys:
            response.status_code = 200
            return response
        else:
            logger.debug(f"bearer found, but unknown api_key  {bearer.credentials}")
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
            )

    # check for cookie
    if not als_token:
        raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
            )

    # check if cookie's value is valid
    try:
        jwt.decode(als_token, config.jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        # Signature has expired
        logger.debug("Signature expired in cookie")
        raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
            )

    response.status_code = 200
    response.content = "Authentication success"
    return response

