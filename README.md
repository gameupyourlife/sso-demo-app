# sso-demo-app

Small Spring Boot demo app to test **SSO via Keycloak**, where Keycloak federates authentication to **Microsoft Entra ID**.

## Architecture

`Browser -> Spring Boot app -> Keycloak -> Microsoft Entra ID`

The app is only configured as an OAuth2 client of Keycloak. Federation to Microsoft Entra ID is configured in Keycloak.

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

## 5) Demo routes (with UI)

- `GET /` public HTML page with login/profile links
- `GET /me` protected HTML profile page with compliance-aware masking for sensitive fields

To login directly:

- `http://localhost:8081/oauth2/authorization/keycloak`

## Configuration (env vars)

- `APP_PORT` (default `8081`)
- `KEYCLOAK_CLIENT_ID` (default `sso-demo-app`)
- `KEYCLOAK_CLIENT_SECRET` (default `change-me`)
- `KEYCLOAK_AUTH_URI` (default local realm authorize endpoint)
- `KEYCLOAK_TOKEN_URI` (default local realm token endpoint)
- `KEYCLOAK_JWK_URI` (default local realm certs endpoint)
- `KEYCLOAK_USERINFO_URI` (default local realm userinfo endpoint)
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
