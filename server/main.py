import logging
from enum import Enum
from typing import List, Optional, Union

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer
from jose import jwt
import httpx
from starlette.responses import StreamingResponse
from starlette.background import BackgroundTask
from starlette.status import HTTP_403_FORBIDDEN, HTTP_502_BAD_GATEWAY


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

@app.on_event('shutdown')
async def shutdown_event():
    await client.aclose()

class Scopes(str, Enum):
    GET = "get"
    POsT = "post"

@app.get("/login", response_class=HTMLResponse)
async def endpoint_login(redirect : Union[str, None] = None):
    """
    This endpoint prints a login form. Currently, this directs the user to google for login.
    The mechanics of OIDC login from google are handled in oidc.py
    """  
    return AUTH_SITE.format(config.oauth_endpoint, config.oauth_redirect_uri, config.oauth_client_id )
    # return RedirectResponse("http://noether.lbl.gov:7443/data_workspace/login")


@app.api_route("/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
async def endpoint_reverse_proxy(request: Request,
                        response: Response,
                        als_token: Union[str, None] = Cookie(default=None),
                        # api_key: APIKey = Depends(get_api_key_from_request),
                        bearer: HTTPBearer = Depends(http_bearer)) -> StreamingResponse:
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

    ### check for api key in bearer
    if bearer: 
        if bearer.credentials in users_db.api_keys:
            return await _reverse_proxy(request)
        else:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
            )
    
    ### check for cookie
    if not als_token:
        return RedirectResponse("/login")
    
    ### check if cookie's value is valid
    try:
        decoded_value = jwt.decode(als_token, config.jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        # Signature has expired
        print("Signature expired in cookie")
        return RedirectResponse("/login")

    response.status_code = 200
    try:
        return await _reverse_proxy(request)
    except Exception as e:
        print(e)
        raise HTTPException(
                status_code=HTTPException, detail=f"Excpetion talking to service {e}"
        )


client = httpx.AsyncClient(
        base_url="http://prefect_server:4200",
        limits=httpx.Limits(max_connections=100),
        timeout=httpx.Timeout(20, connect=20))

async def close(resp: StreamingResponse):
    await resp.aclose()

async def _reverse_proxy(request: Request, scopes: Optional[List[str]] = None) -> StreamingResponse:
    # # cheap and quick scope feature
    # if scopes and request.method.lower() in sceope


    url = httpx.URL(path=request.url.path,
                    query=request.url.query.encode("utf-8"))
    rp_req = client.build_request(request.method, url,
                                  headers=request.headers.raw,
                                  content=await request.body())
    
    rp_resp = await client.send(rp_req, stream=True)
    return StreamingResponse(
        rp_resp.aiter_raw(),
        status_code=rp_resp.status_code,
        headers=rp_resp.headers,
        background=BackgroundTask(close, rp_resp),
    )

