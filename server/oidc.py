from datetime import datetime, timedelta, timezone
from typing import Dict

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from jose import jwk, jwt

from .config import config, google_claims
from .user_db import users_db

oidc_router = APIRouter(prefix="/oidc")


# Singleton keyset, can be refreshed in get_keys()
oauth_validation_keyset = None


class OAuthKeysUnavailableException(Exception):
    pass


class KeyNotFoundError(Exception):
    pass


def contstruct_key(kid: str, keys: Dict):
    for key in keys["keys"]:
        if key["kid"] == kid:
            return jwk.construct(key)


async def find_key(token):
    """finds a key from the configured keys based on the kid claim of the token
    Args:
        token =: token to search for the kid from
    Raises:
        KeyNotFoundError: returned if the token does not have a kid claim
    Returns:
        Key: found key object
    """
    unverified = jwt.get_unverified_header(token)
    kid = unverified.get("kid")
    print(f"~!!!!!!!  kid {kid}")
    if not kid:
        raise KeyNotFoundError("kid not found in jwt")
    keys = await get_keys()
    key = contstruct_key(kid, keys)
    if not key:
        # perhaps the key is stale, try refreshing
        keys = await get_keys(True)
        key = contstruct_key(kid, keys)
        if not key:
            raise KeyError(f"Key not found in fetched keys {keys}")
    return key


def validate_jwt(token, key, access_token):
    jwt.decode(token, key, audience=google_claims["aud"], access_token=access_token)


async def exchange_code(token_url, auth_code, client_id, client_secret, redirect_uri):
    """Method that talks to an IdP to exchange a code for an access_token and/or id_token
    Args:
        token_url ([type]): [description]
        auth_code ([type]): [description]
    """
    print(redirect_uri)
    response = httpx.post(
        url=token_url,
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": auth_code,
            "client_secret": client_secret,
        },
    )
    return response.json()


async def get_keys(stale=False):
    """
    Fetch oauth_validateion_keyset from OUATH_JWKS_URI

    """
    if oauth_validation_keyset and not stale:
        return oauth_validation_keyset

    async with httpx.AsyncClient() as client:
        response = await client.get(config.oauth_jwks_uri)
        if response.is_success:
            return response.json()
        raise OAuthKeysUnavailableException(
            f"Cannot get keyset from OAuth server {response}"
        )


async def get_user_info(user_info_url, access_token):
    """Unused but useful method for getting additional user information"""
    response = httpx.get(
        url=user_info_url, headers={"Authorization": "Bearer " + access_token}
    )
    return response.json()


async def get_user_info(user_info_url, access_token):
    """Unused but useful method for getting additional user information"""
    response = httpx.get(
        url=user_info_url, headers={"Authorization": "Bearer " + access_token}
    )
    return response.json()


@oidc_router.get("/auth/code")
async def endpoint_validate_ouath_code(request: Request):
    """
    Do OAuth2 token exchange with the configured service (Google, ORCID).

    Does a back-channel communicaiton with the service, and returns a
    JWT that we produce.

    """
    print(f"request.query_params {request.query_params}")

    code = request.query_params["code"]
    response_body = await exchange_code(
        config.oauth_token_url,
        code,
        config.oauth_client_id,
        config.oauth_client_secret,
        config.oauth_redirect_uri,
    )
    print(response_body)
    id_token = response_body["id_token"]
    access_token = response_body["access_token"]
    key = await find_key(id_token)
    validate_jwt(id_token, key, access_token)
    # # below is a second method that we used to get more profile info...but then we found that in the html
    # # link to the IdP, we just needed to add the email scope.
    # token_user_info = await get_user_info("https://openidconnect.googleapis.com/v1/userinfo", access_token)
    # if token_user_info['email'] not in users_db.users:
    #     return RedirectResponse(config.oauth_fail_redirect_uri)
    id_claims = jwt.get_unverified_claims(id_token)
    if id_claims["email"] not in users_db.users:
        return RedirectResponse(config.oauth_fail_redirect_uri)
    encoded_jwt = jwt.encode(
        {
            "email": id_claims["email"],
            "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=config.token_time),
        },
        config.jwt_secret,
        algorithm="HS256",
    )
    response = RedirectResponse(config.oauth_success_redirect_uri)
    response.set_cookie(key="als_user", value=id_claims["email"], httponly=True)
    response.set_cookie(
        key="als_token", value=encoded_jwt, httponly=True, max_age=86400
    )
    return response
