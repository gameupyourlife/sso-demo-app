package com.example.ssodemo.web;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class DemoController {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final String complianceClaimName;
    private final Set<String> compliantValues;
    private final boolean failOpenWhenClaimMissing;
    private final Boolean debugForceCompliant;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final ObjectMapper objectMapper;
    private final String defaultLoginRegistration;
    private final String graphDevicesEndpoint;
    private final String graphDeviceByIdEndpointTemplate;
    private final String keycloakBrokerAlias;
    private final HttpClient httpClient;

    public DemoController(
        @Value("${app.sensitive-data.compliance-claim:device_compliant}") String complianceClaimName,
        @Value("${app.sensitive-data.compliant-values:true,1,yes,compliant}") String compliantValues,
        @Value("${app.sensitive-data.fail-open-when-claim-missing:false}") boolean failOpenWhenClaimMissing,
        @Value("${app.sensitive-data.debug-force-compliant:}") String debugForceCompliant,
        @Value("${app.login.default-registration:keycloak}") String defaultLoginRegistration,
        @Value("${app.graph.devices-endpoint:https://graph.microsoft.com/v1.0/me/ownedDevices?$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged}") String graphDevicesEndpoint,
        @Value("${app.graph.device-by-id-endpoint-template:https://graph.microsoft.com/v1.0/devices(deviceId='%s')?$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled}") String graphDeviceByIdEndpointTemplate,
        @Value("${app.keycloak.broker-alias:oidc}") String keycloakBrokerAlias,
        OAuth2AuthorizedClientService authorizedClientService,
        ObjectMapper objectMapper
    ) {
        this.complianceClaimName = complianceClaimName;
        this.compliantValues = parseAllowedValues(compliantValues);
        this.failOpenWhenClaimMissing = failOpenWhenClaimMissing;
        this.debugForceCompliant = parseDebugForceCompliant(debugForceCompliant);
        this.defaultLoginRegistration = defaultLoginRegistration;
        this.graphDevicesEndpoint = graphDevicesEndpoint;
        this.graphDeviceByIdEndpointTemplate = graphDeviceByIdEndpointTemplate;
        this.keycloakBrokerAlias = keycloakBrokerAlias;
        this.authorizedClientService = authorizedClientService;
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        model.addAttribute("app", "sso-demo-app");
        model.addAttribute("now", Instant.now().toString());
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("login", "/oauth2/authorization/" + defaultLoginRegistration);
        model.addAttribute("loginKeycloak", "/oauth2/authorization/keycloak");
        model.addAttribute("loginEntra", "/oauth2/authorization/entra");
        model.addAttribute("loginEntraSaml", "/saml2/authenticate/entra-saml");
        model.addAttribute("samlMetadata", "/saml2/service-provider-metadata/entra-saml");
        model.addAttribute("profile", "/me");
        model.addAttribute("devices", "/device");
        model.addAttribute("saml", "/saml");
        model.addAttribute("logout", "/logout");
        model.addAttribute("message", "You can sign in via Keycloak federation, directly against Microsoft Entra ID (OIDC), or via Entra SAML.");
        return "home";
    }

    @GetMapping("/me")
    public String me(Authentication authentication, Model model) {
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("logout", "/logout");
        model.addAttribute("home", "/");
        model.addAttribute("devices", "/device");
        model.addAttribute("saml", "/saml");
        model.addAttribute("sensitiveDataVisible", false);
        model.addAttribute("complianceClaimName", complianceClaimName);
        model.addAttribute("debugCompliantOverrideEnabled", debugForceCompliant != null);
        model.addAttribute("debugCompliantOverrideValue", debugForceCompliant);
        model.addAttribute("deviceIdClaim", null);
        model.addAttribute("deviceDetails", Collections.emptyMap());
        model.addAttribute("deviceDetailsFetched", false);
        model.addAttribute("deviceDetailsError", null);
        model.addAttribute("deviceDetailsTokenSource", null);

        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            boolean compliant = isCompliant(oidcUser.getClaims());
            model.addAttribute("name", oidcUser.getFullName());
            model.addAttribute("preferredUsername", resolvePreferredUsername(oidcUser));
            model.addAttribute("issuer", oidcUser.getIssuer());
            model.addAttribute("complianceClaimValue", oidcUser.getClaims().get(complianceClaimName));
            model.addAttribute("deviceCompliant", compliant);
            model.addAttribute("sensitiveDataVisible", compliant);

            OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
            populateDeviceDetailsFromClaim(model, oidcUser, authorizedClient);

            if (compliant) {
                model.addAttribute("email", oidcUser.getEmail());
                model.addAttribute("subject", oidcUser.getSubject());
                model.addAttribute("claims", oidcUser.getClaims());
                model.addAttribute("idTokenClaims", oidcUser.getIdToken().getClaims());

                OidcUserInfo userInfo = oidcUser.getUserInfo();
                model.addAttribute("userInfoClaims", userInfo == null ? Collections.emptyMap() : userInfo.getClaims());

                var claims =  extractAccessTokenClaims(authorizedClient);
                model.addAttribute("accessTokenClaims",claims);
                model.addAttribute("accessTokenPresent", authorizedClient != null && authorizedClient.getAccessToken() != null);
                model.addAttribute("refreshTokenPresent", authorizedClient != null && authorizedClient.getRefreshToken() != null);
            }
        } else if (authentication != null) {
            model.addAttribute("principal", authentication.getName());
            model.addAttribute("authorities", authentication.getAuthorities());
        }

        return "me";
    }

    @GetMapping("/device")
    public String device(Authentication authentication, Model model) {
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("logout", "/logout");
        model.addAttribute("home", "/");
        model.addAttribute("profile", "/me");
        model.addAttribute("saml", "/saml");
        model.addAttribute("deviceEndpoint", graphDevicesEndpoint);
        model.addAttribute("devices", Collections.emptyList());
        model.addAttribute("deviceCount", 0);
        model.addAttribute("deviceError", null);
        model.addAttribute("activeClientRegistration", null);
        model.addAttribute("graphAccessTokenSource", null);

        if (authentication == null) {
            model.addAttribute("deviceError", "Authentication is missing.");
            return "device";
        }

        OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            model.addAttribute("deviceError", "No OAuth2 access token available for this session.");
            return "device";
        }

        model.addAttribute("activeClientRegistration", authorizedClient.getClientRegistration().getRegistrationId());

        AccessTokenResolutionResult tokenResolutionResult = resolveGraphAccessToken(authorizedClient);
        if (tokenResolutionResult.error() != null) {
            model.addAttribute("deviceError", tokenResolutionResult.error());
            return "device";
        }

        model.addAttribute("graphAccessTokenSource", tokenResolutionResult.source());

        DeviceQueryResult result = fetchDevices(tokenResolutionResult.accessToken());
        model.addAttribute("devices", result.devices());
        model.addAttribute("deviceCount", result.devices().size());
        model.addAttribute("deviceError", result.error());
        return "device";
    }

    @GetMapping("/saml")
    public String saml(Authentication authentication,
                       @RequestParam(name = "samlError", required = false) String samlError,
                       Model model) {
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("logout", "/logout");
        model.addAttribute("home", "/");
        model.addAttribute("profile", "/me");
        model.addAttribute("devices", "/device");
        model.addAttribute("samlMetadata", "/saml2/service-provider-metadata/entra-saml");
        model.addAttribute("samlError", samlError);
        model.addAttribute("isSamlAuthentication", false);
        model.addAttribute("samlName", null);
        model.addAttribute("samlAttributes", Collections.emptyMap());
        model.addAttribute("samlAuthorities", Collections.emptyList());
        model.addAttribute("samlSessionIndexes", Collections.emptyList());
        model.addAttribute("samlRegistrationId", null);
        model.addAttribute("samlResponsePresent", false);

        if (authentication instanceof Saml2Authentication saml2Authentication) {
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) saml2Authentication.getPrincipal();
            model.addAttribute("isSamlAuthentication", true);
            model.addAttribute("samlName", principal.getName());
            model.addAttribute("samlAttributes", principal.getAttributes());
            model.addAttribute("samlAuthorities", saml2Authentication.getAuthorities());
            model.addAttribute("samlSessionIndexes", principal.getSessionIndexes());
            model.addAttribute("samlRegistrationId", principal.getRelyingPartyRegistrationId());
            model.addAttribute("samlResponsePresent", saml2Authentication.getSaml2Response() != null);
        } else if (authentication != null) {
            model.addAttribute("samlAuthorities", authentication.getAuthorities());
        }

        return "saml";
    }

    private OAuth2AuthorizedClient loadAuthorizedClient(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2AuthenticationToken)) {
            return null;
        }

        return authorizedClientService.loadAuthorizedClient(
            oauth2AuthenticationToken.getAuthorizedClientRegistrationId(),
            oauth2AuthenticationToken.getName()
        );
    }

    private Map<String, Object> extractAccessTokenClaims(OAuth2AuthorizedClient authorizedClient) {
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            return Collections.emptyMap();
        }

        String tokenValue = authorizedClient.getAccessToken().getTokenValue();
        if (tokenValue == null || tokenValue.isBlank()) {
            return Collections.emptyMap();
        }

        String[] tokenParts = tokenValue.split("\\.");
        if (tokenParts.length < 2) {
            return Map.of("_error", "Access token is not a JWT token");
        }

        try {
            byte[] decoded = Base64.getUrlDecoder().decode(tokenParts[1]);
            String payloadJson = new String(decoded, StandardCharsets.UTF_8);
            return objectMapper.readValue(payloadJson, MAP_TYPE);
        } catch (Exception exception) {
            return Map.of("_error", "Access token payload could not be decoded");
        }
    }

    private void populateDeviceDetailsFromClaim(Model model, OidcUser oidcUser, OAuth2AuthorizedClient authorizedClient) {
        String deviceId = resolveDeviceIdClaim(oidcUser);
        model.addAttribute("deviceIdClaim", deviceId);

        if (deviceId == null || deviceId.isBlank()) {
            return;
        }

        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            model.addAttribute("deviceDetailsError", "No OAuth2 token available to fetch device details.");
            return;
        }

        AccessTokenResolutionResult tokenResolutionResult = resolveGraphAccessToken(authorizedClient);
        if (tokenResolutionResult.error() != null) {
            model.addAttribute("deviceDetailsError", tokenResolutionResult.error());
            return;
        }

        model.addAttribute("deviceDetailsTokenSource", tokenResolutionResult.source());
        DeviceLookupResult lookupResult = fetchDeviceById(tokenResolutionResult.accessToken(), deviceId);
        model.addAttribute("deviceDetailsFetched", lookupResult.device() != null && lookupResult.error() == null);
        model.addAttribute("deviceDetails", lookupResult.device() == null ? Collections.emptyMap() : lookupResult.device());
        model.addAttribute("deviceDetailsError", lookupResult.error());
    }

    private String resolveDeviceIdClaim(OidcUser oidcUser) {
        Object raw = oidcUser.getClaims().get("deviceid");
        if (raw == null) {
            raw = oidcUser.getIdToken().getClaims().get("deviceid");
        }

        if (raw instanceof String value && !value.isBlank()) {
            return value;
        }

        return null;
    }

    private AccessTokenResolutionResult resolveGraphAccessToken(OAuth2AuthorizedClient authorizedClient) {
        String keycloakSessionAccessToken = authorizedClient.getAccessToken().getTokenValue();
        if (keycloakSessionAccessToken == null || keycloakSessionAccessToken.isBlank()) {
            return new AccessTokenResolutionResult(null, null, "Session access token is empty.");
        }

        String registrationId = authorizedClient.getClientRegistration().getRegistrationId();
        if (!"keycloak".equalsIgnoreCase(registrationId)) {
            return new AccessTokenResolutionResult(keycloakSessionAccessToken, "oauth2-client-token", null);
        }

        String brokerTokenEndpoint = resolveBrokerTokenEndpoint(authorizedClient);
        if (brokerTokenEndpoint == null) {
            return new AccessTokenResolutionResult(
                null,
                null,
                "Could not resolve Keycloak broker token endpoint from provider token URI."
            );
        }

        return fetchBrokeredAccessToken(keycloakSessionAccessToken, brokerTokenEndpoint);
    }

    private String resolveBrokerTokenEndpoint(OAuth2AuthorizedClient authorizedClient) {
        String tokenUri = authorizedClient.getClientRegistration().getProviderDetails().getTokenUri();
        if (tokenUri == null || tokenUri.isBlank()) {
            return null;
        }

        String marker = "/protocol/openid-connect/token";
        int markerIndex = tokenUri.indexOf(marker);
        if (markerIndex < 0) {
            return null;
        }

        String realmBaseUri = tokenUri.substring(0, markerIndex);
        return realmBaseUri + "/broker/" + keycloakBrokerAlias + "/token";
    }

    private AccessTokenResolutionResult fetchBrokeredAccessToken(String keycloakSessionAccessToken, String brokerTokenEndpoint) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(brokerTokenEndpoint))
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + keycloakSessionAccessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return new AccessTokenResolutionResult(
                    null,
                    null,
                    "Keycloak broker token endpoint failed with HTTP " + response.statusCode()
                        + ". Ensure IdP token storage is enabled and this client can read broker tokens."
                );
            }

            String brokerAccessToken = extractAccessTokenFromBrokerResponse(response.body());
            if (brokerAccessToken == null || brokerAccessToken.isBlank()) {
                return new AccessTokenResolutionResult(
                    null,
                    null,
                    "Keycloak broker token response did not include a usable Entra access token."
                );
            }

            return new AccessTokenResolutionResult(
                brokerAccessToken,
                "keycloak-broker-token:" + keycloakBrokerAlias,
                null
            );
        } catch (Exception exception) {
            return new AccessTokenResolutionResult(
                null,
                null,
                "Failed to fetch broker token from Keycloak: " + exception.getMessage()
            );
        }
    }

    private String extractAccessTokenFromBrokerResponse(String responseBody) {
        if (responseBody == null || responseBody.isBlank()) {
            return null;
        }

        String trimmedBody = responseBody.trim();

        // Keycloak can return either a JSON token payload or the raw access token string.
        if (trimmedBody.startsWith("{")) {
            try {
                Map<String, Object> payload = objectMapper.readValue(trimmedBody, MAP_TYPE);
                Object rawAccessToken = payload.get("access_token");
                if (rawAccessToken instanceof String accessToken && !accessToken.isBlank()) {
                    return accessToken;
                }
            } catch (Exception ignored) {
                return null;
            }
            return null;
        }

        if (trimmedBody.startsWith("\"") && trimmedBody.endsWith("\"")) {
            try {
                String jsonStringToken = objectMapper.readValue(trimmedBody, String.class);
                return (jsonStringToken == null || jsonStringToken.isBlank()) ? null : jsonStringToken;
            } catch (Exception ignored) {
                return null;
            }
        }

        return trimmedBody;
    }

    private Set<String> parseAllowedValues(String csv) {
        return java.util.Arrays.stream(csv.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .map(String::toLowerCase)
            .collect(Collectors.toCollection(HashSet::new));
    }

    private String resolvePreferredUsername(OidcUser oidcUser) {
        if (oidcUser.getPreferredUsername() != null && !oidcUser.getPreferredUsername().isBlank()) {
            return oidcUser.getPreferredUsername();
        }

        return java.util.stream.Stream.of(
                oidcUser.getClaimAsString("upn"),
                oidcUser.getClaimAsString("email"),
                oidcUser.getClaimAsString("oid"),
                oidcUser.getSubject()
            )
            .filter(Objects::nonNull)
            .filter(value -> !value.isBlank())
            .findFirst()
            .orElse(oidcUser.getName());
    }

    private DeviceQueryResult fetchDevices(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return new DeviceQueryResult(Collections.emptyList(), "Access token is empty.");
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(graphDevicesEndpoint))
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return new DeviceQueryResult(
                    Collections.emptyList(),
                    "Graph call failed with HTTP " + response.statusCode() + ". Ensure delegated scope device.read is granted and consented."
                );
            }

            Map<String, Object> payload = objectMapper.readValue(response.body(), MAP_TYPE);
            Object rawValue = payload.get("value");
            if (!(rawValue instanceof Collection<?> collection)) {
                return new DeviceQueryResult(Collections.emptyList(), "Graph response does not contain a value[] collection.");
            }

            List<Map<String, Object>> devices = new ArrayList<>();
            for (Object item : collection) {
                if (item instanceof Map<?, ?> mapItem) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> normalized = (Map<String, Object>) mapItem;
                    devices.add(normalized);
                }
            }
            return new DeviceQueryResult(devices, null);
        } catch (Exception exception) {
            return new DeviceQueryResult(Collections.emptyList(), "Failed to call Graph devices endpoint: " + exception.getMessage());
        }
    }

    private DeviceLookupResult fetchDeviceById(String accessToken, String deviceId) {
        if (accessToken == null || accessToken.isBlank()) {
            return new DeviceLookupResult(null, "Access token is empty.");
        }
        if (deviceId == null || deviceId.isBlank()) {
            return new DeviceLookupResult(null, "deviceid claim is empty.");
        }

        try {
            String encodedDeviceId = URLEncoder.encode(deviceId, StandardCharsets.UTF_8).replace("+", "%20");
            String endpoint = String.format(graphDeviceByIdEndpointTemplate, encodedDeviceId);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return new DeviceLookupResult(
                    null,
                    "Graph device lookup failed with HTTP " + response.statusCode()
                        + ". Ensure delegated permissions (e.g. Device.Read) are granted and consented."
                );
            }

            Map<String, Object> payload = objectMapper.readValue(response.body(), MAP_TYPE);
            return new DeviceLookupResult(payload, null);
        } catch (Exception exception) {
            return new DeviceLookupResult(null, "Failed to fetch Graph device by id: " + exception.getMessage());
        }
    }

    private DeviceLookupResult fetchDeviceFromOwnedDevices(String accessToken, String deviceId) {
        DeviceQueryResult queryResult = fetchDevices(accessToken);
        if (queryResult.error() != null) {
            return new DeviceLookupResult(null, queryResult.error());
        }

        String normalizedDeviceId = deviceId.trim();
        for (Map<String, Object> device : queryResult.devices()) {
            Object rawId = device.get("deviceId");
            if (rawId instanceof String id && normalizedDeviceId.equalsIgnoreCase(id.trim())) {
                return new DeviceLookupResult(device, null);
            }
        }

        return new DeviceLookupResult(
            null,
            "Device with claim id " + deviceId + " was not found in Graph /me/ownedDevices response."
        );
    }

    private record DeviceQueryResult(List<Map<String, Object>> devices, String error) {
    }

    private record DeviceLookupResult(Map<String, Object> device, String error) {
    }

    private record AccessTokenResolutionResult(String accessToken, String source, String error) {
    }

    private boolean isCompliant(Map<String, Object> claims) {
        if (debugForceCompliant != null) {
            return debugForceCompliant;
        }

        Object rawValue = claims.get(complianceClaimName);
        if (rawValue == null) {
            return failOpenWhenClaimMissing;
        }

        if (rawValue instanceof Boolean booleanValue) {
            return booleanValue;
        }

        if (rawValue instanceof Collection<?> values) {
            for (Object value : values) {
                if (value != null && compliantValues.contains(value.toString().trim().toLowerCase())) {
                    return true;
                }
            }
            return false;
        }

        String normalized = rawValue.toString().trim().toLowerCase();
        return compliantValues.contains(normalized);
    }

    private Boolean parseDebugForceCompliant(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return null;
        }

        if ("true".equalsIgnoreCase(rawValue.trim())) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(rawValue.trim())) {
            return Boolean.FALSE;
        }

        throw new IllegalArgumentException("app.sensitive-data.debug-force-compliant must be true, false or empty");
    }
}

