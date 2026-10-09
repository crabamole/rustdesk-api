-- OIDC logins in progress: any api-server pod may finish a login another pod started.
CREATE TABLE oidc_login (
    code           text PRIMARY KEY,               -- login code, the IdP's `state`
    created_at     timestamptz NOT NULL DEFAULT now(),
    provider       text,                           -- oauth2::Provider; the provider is rebuilt from it
    callback_url   text,
    provider_state text,                           -- oauth2::pkce::ProviderLogin
    provider_nonce text,
    code_verifier  text,
    return_to      text NOT NULL,
    code_challenge text NOT NULL,
    rustdesk_id    text NOT NULL,
    uuid           text NOT NULL,
    device_name    text NOT NULL,
    device_os      text NOT NULL,
    device_type    text NOT NULL,
    requester_ip   text,
    callback_at    timestamptz,                    -- set by the one callback allowed to run
    sub            text,
    name           text,
    email          text,
    result         text UNIQUE,
    result_at      timestamptz
);
CREATE INDEX oidc_login_created_at ON oidc_login (created_at);
