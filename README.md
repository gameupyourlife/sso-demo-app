# sso-demo-app

Small Spring Boot demo app to test **SSO via Keycloak** (federated to Microsoft Entra ID), **directly via Microsoft Entra ID (OIDC)**, or **Microsoft Entra ID via SAML**.

## Architecture

`Browser -> Spring Boot app -> (Keycloak -> Microsoft Entra ID) or (Microsoft Entra ID direct OIDC) or (Microsoft Entra ID SAML)`

The app supports two OAuth2 client registrations:
- `keycloak` (federated path)
- `entra` (direct path)

And one SAML relying-party registration:
- `entra-saml` (direct SAML path)

## 1) Start Keycloak (local demo)

```powershell
docker compose up -d
```

Open Keycloak Admin UI: `http://localhost:8080/admin`

- Admin user: `admin`
- Password: `admin`

## 2) Configure Keycloak realm + client

Create realm: `sso-demo`

Create client:
- Client ID: `sso-demo-app`
- Client type: `OpenID Connect`
- Access type: `confidential`
- Valid redirect URI: `http://localhost:8081/login/oauth2/code/keycloak`
- Web origin: `http://localhost:8081`

Copy client secret and set environment variable before app startup:

```powershell
$env:KEYCLOAK_CLIENT_SECRET="your-secret"
```

## 3) Configure Entra ID as Identity Provider in Keycloak

In Keycloak realm `sso-demo`:

1. Go to **Identity providers**.
2. Add provider **Microsoft** (OIDC).
3. In Microsoft Entra ID, register an app for Keycloak and copy:
   - Client ID
   - Client secret
   - Tenant/authority endpoints
4. Fill those values in Keycloak Microsoft IdP settings.
5. Enable first broker login flow (default is fine for demo).

After this, Keycloak login page can offer "Microsoft" login.

## 4) Run the Spring Boot app

```powershell
mvn spring-boot:run
```

App runs on `http://localhost:8081`.

## 4a) Deploy on Coolify (existing Keycloak, no local Keycloak container)

This repository now contains a production-ready `Dockerfile` for the Spring Boot app only.

In Coolify:

1. Create a new app from this Git repository.
2. Use the `Dockerfile` in the repository root.
3. Expose port `8081`.
4. Set the environment variables for your **existing** Keycloak instance.

Minimum Keycloak-related variables for a browser login flow:

```powershell
$env:APP_PORT="8081"
$env:APP_REDIRECT_URI="https://your-domain.example/login/oauth2/code/{registrationId}"
$env:KEYCLOAK_CLIENT_ID="sso-demo-app"
$env:KEYCLOAK_CLIENT_SECRET="your-client-secret"
$env:KEYCLOAK_ISSUER_URI="https://keycloak.example.com/realms/sso-demo"
$env:KEYCLOAK_AUTH_URI="https://keycloak.example.com/realms/sso-demo/protocol/openid-connect/auth"
$env:KEYCLOAK_TOKEN_URI="https://keycloak.example.com/realms/sso-demo/protocol/openid-connect/token"
$env:KEYCLOAK_JWK_URI="https://keycloak.example.com/realms/sso-demo/protocol/openid-connect/certs"
$env:KEYCLOAK_USERINFO_URI="https://keycloak.example.com/realms/sso-demo/protocol/openid-connect/userinfo"
```


If you want direct Entra sign-in instead of Keycloak, set the `ENTRA_*` variables and `LOGIN_DEFAULT_REGISTRATION=entra`.

You do **not** need to run the `docker-compose.yml` Keycloak service for this deployment.

## 5) Demo routes (with UI)

- `GET /` public HTML page with login/profile links
- `GET /me` protected HTML profile page with compliance-aware masking for sensitive fields
- `GET /device` protected HTML page that calls Microsoft Graph to list user devices
- `GET /saml` protected HTML page showing SAML attributes, rights (authorities), and session details

To login directly:

- `http://localhost:8081/oauth2/authorization/keycloak`
- `http://localhost:8081/oauth2/authorization/entra`
- `http://localhost:8081/saml2/authenticate/entra-saml`

## Configuration (env vars)

- `APP_PORT` (default `8081`)
- `KEYCLOAK_CLIENT_ID` (default `sso-demo-app`)
- `KEYCLOAK_CLIENT_SECRET` (default `change-me`)
- `KEYCLOAK_AUTH_URI` (default local realm authorize endpoint)
- `KEYCLOAK_TOKEN_URI` (default local realm token endpoint)
- `KEYCLOAK_JWK_URI` (default local realm certs endpoint)
- `KEYCLOAK_USERINFO_URI` (default local realm userinfo endpoint)
- `ENTRA_CLIENT_ID` (client ID for direct Entra app registration)
- `ENTRA_CLIENT_SECRET` (client secret for direct Entra app registration)
- `ENTRA_TENANT_ID` (default `common`; use your tenant GUID for production)
- `ENTRA_AUTH_URI` (optional override for authorize endpoint)
- `ENTRA_TOKEN_URI` (optional override for token endpoint)
- `ENTRA_JWK_URI` (optional override for JWKS endpoint)
- `ENTRA_USERINFO_URI` (optional override for UserInfo endpoint)
- `ENTRA_SAML_METADATA_URI` (default `https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml`)
- `ENTRA_SAML_APP_ID` (optional; used to resolve app-specific federation metadata)
- `GRAPH_DEVICES_ENDPOINT` (default `https://graph.microsoft.com/v1.0/me/ownedDevices?...`)
- `LOGIN_DEFAULT_REGISTRATION` (default `keycloak`; can be `entra`)
- `LOGIN_PROMPT` (default `select_account`; keeps account picker enabled on Entra login)
- `COMPLIANCE_CLAIM` (default `device_compliant`)
- `COMPLIANCE_VALUES` (default `true,1,yes,compliant`)
- `COMPLIANCE_FAIL_OPEN` (default `false`)
- `COMPLIANCE_DEBUG_FORCE` (default empty; set to `true` or `false` to override compliance gate for debugging)

## Device-based SSO

This project now intentionally relies on Microsoft products for device-based SSO:

- Device trust/compliance is evaluated in **Microsoft Entra ID Conditional Access** (with **Microsoft Intune** compliance).
- Silent SSO is handled by the Microsoft identity platform on managed/trusted devices.
- The Spring Boot app does not implement custom trusted-device cookies.
- The app can consume a claim (default `device_compliant`) to decide whether sensitive data is shown.

Recommended setup:

1. In Entra ID, create Conditional Access policy requiring compliant (or hybrid joined) device for your Keycloak-brokered app sign-in.
2. In Intune, define compliance policies and ensure target devices become compliant.
3. In Keycloak, map the upstream Entra claim that represents compliance into the token claim used by this app (`COMPLIANCE_CLAIM`).
4. Keep `COMPLIANCE_FAIL_OPEN=false` to avoid exposing sensitive data when compliance claim is missing.

To always allow user account selection when redirected to Entra ID, keep `LOGIN_PROMPT=select_account`.

If you want direct Entra sign-in to be the default redirect target for protected pages, set `LOGIN_DEFAULT_REGISTRATION=entra`.

For `/device`, direct Entra sign-in should include delegated `device.read` scope in the `entra` registration so Graph can return the signed-in user's devices.

For SAML setup, open your service-provider metadata at:

- `http://localhost:8081/saml2/service-provider-metadata/entra-saml`

Use that metadata in Microsoft Entra Enterprise App SAML configuration.

If metadata previously returned an error page, ensure SAML metadata is enabled in security configuration and that `ENTRA_SAML_METADATA_URI` is reachable from the app runtime.

For signature validation issues (`Signature ... was not valid`), prefer metadata-based configuration and point `ENTRA_SAML_METADATA_URI` to your exact Entra federation metadata URL (tenant-specific, and app-specific variant if required by your tenant policy).

Default config now uses the app-specific metadata pattern with `?appid=...`. If SAML login still fails, open `/saml` after a failed login and inspect the surfaced `SAML login error` message.

## Compliance-aware masking

Signed-in users can still access `/me`, but sensitive user data is only shown when the configured claim indicates a compliant sign-in context.

When sensitive data is visible, `/me` shows claims in separate sections for:
- merged OIDC claims (`OidcUser.getClaims()`)
- ID token claims
- UserInfo claims
- decoded access token payload claims (if the access token is JWT formatted)

Example PowerShell config:

```powershell
$env:COMPLIANCE_CLAIM="device_compliant"
$env:COMPLIANCE_VALUES="true,compliant"
$env:COMPLIANCE_FAIL_OPEN="false"
```

If your compliance info comes from Entra ID through Keycloak, map the corresponding upstream claim to the claim name used in `COMPLIANCE_CLAIM`.

### Debug override (local testing only)

For troubleshooting, you can force the compliance decision without changing Entra/Intune policies:

```powershell
$env:COMPLIANCE_DEBUG_FORCE="true"
```

or

```powershell
$env:COMPLIANCE_DEBUG_FORCE="false"
```

Leave it empty to use normal claim-based behavior.

## Test

```powershell
mvn test
```
