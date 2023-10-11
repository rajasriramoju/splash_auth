import os




def test_config(monkeypatch):

    monkeypatch.setenv("JWT_SECRET", "secret")
    monkeypatch.setenv("TOKEN_EXP_TIME", 2)
    monkeypatch.setenv("OAUTH_AUTH_ENDPOINT", "http://magrathea.com")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "slartibartfast")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "mousey")
    monkeypatch.setenv("OAUTH_TOKEN_URI", "http://earth.com/.well-known/openid-configuration")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "http://earth.com")
    monkeypatch.setenv("OUATH_FAIL_REDIRECT_URI", "http://whale.com")
    monkeypatch.setenv("OUATH_SUCCESS_REDIRECT_URI", "http://dolphin.com")
    monkeypatch.setenv("OUATH_JWKS_URI", "http://hearofgold.com")
    monkeypatch.setenv("HTTP_CLIENT_MAX_CONNECTIONS", 101)
    monkeypatch.setenv("HTTP_CLIENT_TIMEOUT_ALL",  1.0)
    monkeypatch.setenv("HTTP_CLIENT_TIMEOUT_CONNECT", 4.0)
    monkeypatch.setenv("HTTP_CLIENT_TIMEOUT_POOL", 10)
    from splash_auth.config import Config
    # Test default values
    config = Config()
    print(config)
    assert config.jwt_secret == "secret"
    assert config.token_exp_time == 2
    assert config.oauth_endpoint == "http://magrathea.com"
    assert config.oauth_client_id == "slartibartfast"
    assert config.oauth_client_secret == "mousey"
    assert config.oauth_redirect_uri == "http://earth.com"
    assert config.oauth_token_url == "http://earth.com/.well-known/openid-configuration"
    assert config.oauth_success_redirect_uri == "http://dolphin.com"
    assert config.oauth_fail_redirect_uri == "http://whale.com"
    assert config.oauth_jwks_uri == "http://hearofgold.com"
    assert config.http_client_max_connections == 101
    assert config.http_client_timeout_all == 1.0
    assert config.http_client_timeout_connect == 4.0
    assert config.http_client_timeout_pool == 10
    
    
