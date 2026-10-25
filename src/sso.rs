use std::{sync::LazyLock, time::Duration};

use chrono::Utc;
use derive_more::{AsRef, Deref, Display, From, Into};
use url::Url;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    auth,
    auth::{AuthMethod, AuthTokens, BW_EXPIRATION, DEFAULT_REFRESH_VALIDITY, TokenWrapper},
    db::{
        DbConn,
        models::{Device, OIDCAuthenticatedUser, SsoAuth, SsoUser, User},
    },
    sso_client::Client,
};

pub static FAKE_SSO_IDENTIFIER: &str = "00000000-01DC-01DC-01DC-000000000000";

static SSO_JWT_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|sso", CONFIG.domain_origin()));

pub static SSO_AUTH_EXPIRATION: LazyLock<chrono::Duration> =
    LazyLock::new(|| chrono::TimeDelta::try_minutes(10).unwrap());

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCCode(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
    Into,
)]
#[deref(forward)]
#[into(owned)]
pub struct OIDCCodeChallenge(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    Into,
)]
#[deref(forward)]
#[into(owned)]
pub struct OIDCCodeVerifier(String);

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCState(String);

#[derive(Debug, Serialize, Deserialize)]
struct SsoTokenJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,
}

pub fn encode_ssotoken_claims() -> String {
    let time_now = Utc::now();
    let claims = SsoTokenJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + chrono::TimeDelta::try_minutes(2).unwrap()).timestamp(),
        iss: SSO_JWT_ISSUER.to_string(),
        sub: "vaultwarden".to_owned(),
    };

    auth::encode_jwt(&claims)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BasicTokenClaims {
    iat: Option<i64>,
    nbf: Option<i64>,
    exp: i64,
}

#[derive(Deserialize)]
struct BasicTokenClaimsValidation {
    exp: u64,
    iss: String,
}

impl BasicTokenClaims {
    fn nbf(&self) -> i64 {
        self.nbf.or(self.iat).unwrap_or_else(|| Utc::now().timestamp())
    }
}

fn decode_token_claims(token_name: &str, token: &str) -> ApiResult<BasicTokenClaims> {
    // We need to manually validate this token, since `insecure_decode` does not do this
    match jsonwebtoken::dangerous::insecure_decode::<BasicTokenClaimsValidation>(token) {
        Ok(btcv) => {
            let now = jsonwebtoken::get_current_timestamp();
            let validate_claim = btcv.claims;
            // Validate the exp in the claim with a leeway of 60 seconds, same as jsonwebtoken does
            if validate_claim.exp < now - 60 {
                err_silent!(format!("Expired Signature for base token claim from {token_name}"))
            }
            if validate_claim.iss.ne(&CONFIG.sso_authority()) {
                err_silent!(format!("Invalid Issuer for base token claim from {token_name}"))
            }

            // All is validated and ok, lets decode again using the wanted struct
            let btc = jsonwebtoken::dangerous::insecure_decode::<BasicTokenClaims>(token).unwrap();
            Ok(btc.claims)
        }
        Err(err) => err_silent!(format!("Failed to decode basic token claims from {token_name}: {err}")),
    }
}

pub fn decode_state(base64_state: &str) -> ApiResult<OIDCState> {
    let state = if let Ok(vec) = data_encoding::BASE64.decode(base64_state.as_bytes()) {
        if let Ok(valid) = String::from_utf8(vec) {
            OIDCState(valid)
        } else {
            err!(format!("Invalid utf8 chars in {} after base64 decoding", base64_state.escape_debug()))
        }
    } else {
        err!(format!("Failed to decode {} using base64", base64_state.escape_debug()))
    };

    Ok(state)
}

// redirect_uri from: https://github.com/bitwarden/server/blob/main/src/Identity/IdentityServer/StaticClientStore.cs
pub async fn authorize_url(
    state: OIDCState,
    client_challenge: OIDCCodeChallenge,
    client_id: &str,
    raw_redirect_uri: &str,
    binding_hash: Option<String>,
    conn: DbConn,
) -> ApiResult<Url> {
    // The desktop app uses the localhost callback when it can't register the custom scheme (AppImage, dev builds)
    let localhost_redirect_uri =
        (8065..=8070).map(|port| format!("http://localhost:{port}")).find(|uri| uri == raw_redirect_uri);

    let redirect_uri = match client_id {
        "web" | "browser" => format!("{}/sso-connector.html", CONFIG.domain()),
        "desktop" => localhost_redirect_uri.unwrap_or_else(|| "bitwarden://sso-callback".to_owned()),
        "mobile" => "bitwarden://sso-callback".to_owned(),
        "cli" => {
            let Some(uri) = localhost_redirect_uri else {
                err!(format!("Unsupported redirect uri {}", raw_redirect_uri.escape_debug()))
            };
            uri
        }
        _ => err!(format!("Unsupported client {}", client_id.escape_debug())),
    };

    let (auth_url, sso_auth) = Client::authorize_url(state, client_challenge, redirect_uri, binding_hash).await?;
    sso_auth.save(&conn).await?;
    Ok(auth_url)
}

#[derive(
    Clone,
    Debug,
    Default,
    DieselNewType,
    FromForm,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    AsRef,
    Deref,
    Display,
    From,
)]
#[deref(forward)]
#[from(forward)]
pub struct OIDCIdentifier(String);

impl OIDCIdentifier {
    fn new(issuer: &str, subject: &str) -> Self {
        OIDCIdentifier(format!("{issuer}/{subject}"))
    }
}

fn check_hosted_domain(hd: Option<&str>, allowed: Option<&str>) -> EmptyResult {
    let Some(allowed) = allowed.map(str::trim).filter(|allowed| !allowed.is_empty()) else {
        return Ok(());
    };

    // Fails closed: a set but degenerate list (e.g. " , ") matches nothing.
    match hd {
        Some(hd) if allowed.split(',').map(str::trim).any(|d| !d.is_empty() && d.eq_ignore_ascii_case(hd)) => Ok(()),
        _ => err!("Account is not part of an allowed hosted domain"),
    }
}

// Google is only authoritative for `@gmail.com` and Workspace (`hd`) addresses, see
// https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
fn authoritative_email_verified(
    issuer: &str,
    email: &str,
    hd: Option<&str>,
    email_verified: Option<bool>,
) -> Option<bool> {
    let is_google = matches!(issuer, "https://accounts.google.com" | "accounts.google.com");
    if is_google && !email.ends_with("@gmail.com") && hd.is_none_or(str::is_empty) {
        return Some(false);
    }
    email_verified
}

// During the 2FA flow we will
//  - retrieve the user information and then only discover he needs 2FA.
//  - second time we will rely on `SsoAuth.auth_response` since the `code` has already been exchanged,
//    after checking the PKCE verifier again like upstream does on every redemption.
// The `SsoAuth` will ensure that the user is authorized only once.
pub async fn exchange_code(
    code: &OIDCCode,
    client_verifier: OIDCCodeVerifier,
    conn: &DbConn,
) -> ApiResult<(SsoAuth, OIDCAuthenticatedUser)> {
    use openidconnect::OAuth2TokenResponse;

    let Some(mut sso_auth) = SsoAuth::find_by_code(code, conn).await else {
        err!("Invalid code cannot retrieve sso auth")
    };

    if let Some(authenticated_user) = sso_auth.auth_response.clone() {
        Client::check_client_verifier(&client_verifier, &sso_auth)?;
        return Ok((sso_auth, authenticated_user));
    }

    let code = match (sso_auth.code_response.clone(), sso_auth.code_response_error.as_ref()) {
        (Some(code), None) => code,
        (_, Some(re)) => {
            let error_msg = format!(
                "SSO authorization failed: {}, {}",
                re.error,
                re.error_description.as_ref().unwrap_or(&String::new())
            );
            sso_auth.delete(conn).await?;
            err!(error_msg);
        }
        (None, _) => {
            sso_auth.delete(conn).await?;
            err!("Missing authorization provider return");
        }
    };

    let client = Client::cached().await?;
    let (token_response, id_claims) = client.exchange_code(code, client_verifier, &sso_auth).await?;

    let allowed_hosted_domains = CONFIG.sso_allowed_hosted_domains();
    if let Err(err) =
        check_hosted_domain(id_claims.additional_claims().hd.as_deref(), allowed_hosted_domains.as_deref())
    {
        sso_auth.delete(conn).await?;
        return Err(err);
    }

    let user_info = client.user_info(token_response.access_token().to_owned()).await?;

    let email = match id_claims.email().or(user_info.email()) {
        None => err!("Neither id token nor userinfo contained an email"),
        Some(e) => e.to_string().to_lowercase(),
    };

    let email_verified = authoritative_email_verified(
        id_claims.issuer().as_str(),
        &email,
        id_claims.additional_claims().hd.as_deref(),
        id_claims.email_verified().or(user_info.email_verified()),
    );

    let user_name = id_claims.preferred_username().or(user_info.preferred_username()).map(|un| un.to_string());

    let refresh_token = token_response.refresh_token().map(openidconnect::RefreshToken::secret);
    if refresh_token.is_none() && CONFIG.sso_scopes_vec().contains(&"offline_access".to_owned()) {
        error!("Scope offline_access is present but response contain no refresh_token");
    }

    let identifier = OIDCIdentifier::new(id_claims.issuer(), id_claims.subject());

    let authenticated_user = OIDCAuthenticatedUser {
        refresh_token: refresh_token.cloned(),
        access_token: token_response.access_token().secret().clone(),
        expires_in: token_response.expires_in(),
        identifier: identifier.clone(),
        email: email.clone(),
        email_verified,
        user_name: user_name.clone(),
    };

    debug!("Authenticated user {authenticated_user:?}");
    sso_auth.auth_response = Some(authenticated_user.clone());
    sso_auth.updated_at = Utc::now().naive_utc();
    sso_auth.save(conn).await?;

    Ok((sso_auth, authenticated_user))
}

// User has passed 2FA flow we can delete auth info from database
pub async fn redeem(
    device: &Device,
    user: &User,
    client_id: Option<String>,
    sso_user: Option<SsoUser>,
    sso_auth: SsoAuth,
    auth_user: OIDCAuthenticatedUser,
    conn: &DbConn,
) -> ApiResult<AuthTokens> {
    sso_auth.delete(conn).await?;

    if sso_user.is_none() {
        let user_sso = SsoUser {
            user_uuid: user.uuid.clone(),
            identifier: auth_user.identifier.clone(),
        };
        user_sso.save(conn).await?;
    }

    if CONFIG.sso_auth_only_not_session() {
        Ok(AuthTokens::new(device, user, AuthMethod::Sso, client_id))
    } else {
        let now = Utc::now();

        let (ap_nbf, ap_exp) =
            match (decode_token_claims("access_token", &auth_user.access_token), auth_user.expires_in) {
                (Ok(ap), _) => (ap.nbf(), ap.exp),
                (Err(_), Some(exp)) => (now.timestamp(), (now + exp).timestamp()),
                _ => err!("Non jwt access_token and empty expires_in"),
            };

        let access_claims =
            auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, AuthMethod::Sso.scope_vec(), client_id, now);

        create_auth_tokens_impl(device, auth_user.refresh_token, access_claims, auth_user.access_token)
    }
}

// We always return a refresh_token (with no refresh_token some secrets are not displayed in the web front).
// If there is no SSO refresh_token, we keep the access_token to be able to call user_info to check for validity
pub fn create_auth_tokens(
    device: &Device,
    user: &User,
    client_id: Option<String>,
    refresh_token: Option<String>,
    access_token: String,
    expires_in: Option<Duration>,
) -> ApiResult<AuthTokens> {
    if CONFIG.sso_auth_only_not_session() {
        Ok(AuthTokens::new(device, user, AuthMethod::Sso, client_id))
    } else {
        let now = Utc::now();

        let (ap_nbf, ap_exp) = match (decode_token_claims("access_token", &access_token), expires_in) {
            (Ok(ap), _) => (ap.nbf(), ap.exp),
            (Err(_), Some(exp)) => (now.timestamp(), (now + exp).timestamp()),
            _ => err!("Non jwt access_token and empty expires_in"),
        };

        let access_claims =
            auth::LoginJwtClaims::new(device, user, ap_nbf, ap_exp, AuthMethod::Sso.scope_vec(), client_id, now);

        create_auth_tokens_impl(device, refresh_token, access_claims, access_token)
    }
}

fn create_auth_tokens_impl(
    device: &Device,
    refresh_token: Option<String>,
    access_claims: auth::LoginJwtClaims,
    access_token: String,
) -> ApiResult<AuthTokens> {
    let (nbf, exp, token) = if let Some(rt) = refresh_token {
        match decode_token_claims("refresh_token", &rt) {
            Err(_) => {
                let time_now = Utc::now();
                let exp = (time_now + *DEFAULT_REFRESH_VALIDITY).timestamp();
                debug!("Non jwt refresh_token (expiration set to {exp})");
                (time_now.timestamp(), exp, TokenWrapper::Refresh(rt))
            }
            Ok(refresh_payload) => {
                debug!("Refresh_payload: {refresh_payload:?}");
                (refresh_payload.nbf(), refresh_payload.exp, TokenWrapper::Refresh(rt))
            }
        }
    } else {
        debug!("No refresh_token present");
        (access_claims.nbf, access_claims.exp, TokenWrapper::Access(access_token))
    };

    let refresh_claims = auth::RefreshJwtClaims {
        nbf,
        exp,
        iss: auth::JWT_LOGIN_ISSUER.to_string(),
        sub: AuthMethod::Sso,
        device_token: device.refresh_token.clone(),
        token: Some(token),
    };

    Ok(AuthTokens {
        refresh_claims,
        access_claims,
    })
}

// This endpoint is called in two case
//  - the session is close to expiration we will try to extend it
//  - the user is going to make an action and we check that the session is still valid
pub async fn exchange_refresh_token(
    device: &Device,
    user: &User,
    client_id: Option<String>,
    refresh_claims: auth::RefreshJwtClaims,
) -> ApiResult<AuthTokens> {
    let exp = refresh_claims.exp;
    match refresh_claims.token {
        Some(TokenWrapper::Refresh(refresh_token)) => {
            // Use new refresh_token if returned
            let (new_refresh_token, access_token, expires_in) =
                Client::exchange_refresh_token(refresh_token.clone()).await?;

            create_auth_tokens(
                device,
                user,
                client_id,
                new_refresh_token.or(Some(refresh_token)),
                access_token,
                expires_in,
            )
        }
        Some(TokenWrapper::Access(access_token)) => {
            let now = Utc::now();
            let exp_limit = (now + *BW_EXPIRATION).timestamp();

            if exp < exp_limit {
                err_silent!("Access token is close to expiration but we have no refresh token")
            }

            Client::check_validity(access_token.clone()).await?;

            let access_claims = auth::LoginJwtClaims::new(
                device,
                user,
                now.timestamp(),
                exp,
                AuthMethod::Sso.scope_vec(),
                client_id,
                now,
            );

            create_auth_tokens_impl(device, None, access_claims, access_token)
        }
        None => err!("No token present while in SSO"),
    }
}

#[cfg(test)]
mod tests {
    use super::{authoritative_email_verified, check_hosted_domain};

    const GOOGLE: &str = "https://accounts.google.com";

    #[test]
    fn google_consumer_email_verified_is_kept_for_gmail() {
        assert_eq!(authoritative_email_verified(GOOGLE, "alice@gmail.com", None, Some(true)), Some(true));
    }

    #[test]
    fn google_custom_domain_with_hd_keeps_email_verified() {
        assert_eq!(
            authoritative_email_verified(GOOGLE, "alice@yourcorp.com", Some("yourcorp.com"), Some(true)),
            Some(true)
        );
    }

    #[test]
    fn google_custom_domain_without_hd_is_not_verified() {
        assert_eq!(authoritative_email_verified(GOOGLE, "alice@yourcorp.com", None, Some(true)), Some(false));
        assert_eq!(authoritative_email_verified(GOOGLE, "alice@yourcorp.com", None, None), Some(false));
        assert_eq!(authoritative_email_verified(GOOGLE, "alice@yourcorp.com", Some(""), Some(true)), Some(false));
    }

    #[test]
    fn google_bare_issuer_behaves_like_https_issuer() {
        assert_eq!(
            authoritative_email_verified("accounts.google.com", "alice@yourcorp.com", None, Some(true)),
            Some(false)
        );
        assert_eq!(
            authoritative_email_verified("accounts.google.com", "alice@gmail.com", None, Some(true)),
            Some(true)
        );
    }

    #[test]
    fn non_google_issuer_is_untouched() {
        assert_eq!(
            authoritative_email_verified("https://sso.example.com", "alice@yourcorp.com", None, Some(true)),
            Some(true)
        );
        assert_eq!(authoritative_email_verified("https://sso.example.com", "alice@yourcorp.com", None, None), None);
    }

    #[test]
    fn hosted_domain_unset_allows_any_claim() {
        assert!(check_hosted_domain(None, None).is_ok());
        assert!(check_hosted_domain(Some("other.org"), None).is_ok());
        assert!(check_hosted_domain(None, Some("  ")).is_ok());
    }

    #[test]
    fn hosted_domain_missing_claim_is_rejected() {
        assert!(check_hosted_domain(None, Some("example.com")).is_err());
    }

    #[test]
    fn hosted_domain_degenerate_list_rejects_all() {
        assert!(check_hosted_domain(None, Some(" , ")).is_err());
        assert!(check_hosted_domain(Some(""), Some(" , ")).is_err());
        assert!(check_hosted_domain(Some("example.com"), Some(" , ")).is_err());
    }

    #[test]
    fn hosted_domain_not_in_list_is_rejected() {
        assert!(check_hosted_domain(Some("other.org"), Some("example.com,example.org")).is_err());
    }

    #[test]
    fn hosted_domain_match_ignores_case_and_whitespace() {
        assert!(check_hosted_domain(Some("Example.ORG"), Some(" example.com , example.org ")).is_ok());
    }
}
