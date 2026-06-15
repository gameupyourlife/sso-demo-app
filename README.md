# sso-demo-app

Small Spring Boot demo app to test **SSO via Keycloak**, where Keycloak federates authentication to **Microsoft Entra ID**.

## Architecture

`Browser -> Spring Boot app -> Keycloak -> Microsoft Entra ID`

The app is only configured as an OAuth2 client of Keycloak. Federation to Microsoft Entra ID is configured in Keycloak.

## 1) Start Keycloak (local demo)

```bash
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

```bash
export KEYCLOAK_CLIENT_SECRET=your-secret
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

```bash
mvn spring-boot:run
```

App runs on `http://localhost:8081`.

## 5) Demo endpoints

- `GET /` public app info + links
- `GET /me` protected endpoint showing OIDC claims after login

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

## Test

```bash
mvn test
```

