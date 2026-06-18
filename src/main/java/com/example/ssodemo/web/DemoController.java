package com.example.ssodemo.web;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

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

    public DemoController(
        @Value("${app.sensitive-data.compliance-claim:device_compliant}") String complianceClaimName,
        @Value("${app.sensitive-data.compliant-values:true,1,yes,compliant}") String compliantValues,
        @Value("${app.sensitive-data.fail-open-when-claim-missing:false}") boolean failOpenWhenClaimMissing,
        @Value("${app.sensitive-data.debug-force-compliant:}") String debugForceCompliant,
        OAuth2AuthorizedClientService authorizedClientService,
        ObjectMapper objectMapper
    ) {
        this.complianceClaimName = complianceClaimName;
        this.compliantValues = parseAllowedValues(compliantValues);
        this.failOpenWhenClaimMissing = failOpenWhenClaimMissing;
        this.debugForceCompliant = parseDebugForceCompliant(debugForceCompliant);
        this.authorizedClientService = authorizedClientService;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        model.addAttribute("app", "sso-demo-app");
        model.addAttribute("now", Instant.now().toString());
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("login", "/oauth2/authorization/keycloak");
        model.addAttribute("profile", "/me");
        model.addAttribute("logout", "/logout");
        model.addAttribute("message", "Login happens against Keycloak with federation to Microsoft Entra ID; device-based access should be enforced by Entra ID and Intune policies.");
        return "home";
    }

    @GetMapping("/me")
    public String me(Authentication authentication, Model model) {
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("logout", "/logout");
        model.addAttribute("home", "/");
        model.addAttribute("sensitiveDataVisible", false);
        model.addAttribute("complianceClaimName", complianceClaimName);
        model.addAttribute("debugCompliantOverrideEnabled", debugForceCompliant != null);
        model.addAttribute("debugCompliantOverrideValue", debugForceCompliant);

        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            boolean compliant = isCompliant(oidcUser.getClaims());
            model.addAttribute("name", oidcUser.getFullName());
            model.addAttribute("preferredUsername", oidcUser.getPreferredUsername());
            model.addAttribute("issuer", oidcUser.getIssuer());
            model.addAttribute("complianceClaimValue", oidcUser.getClaims().get(complianceClaimName));
            model.addAttribute("deviceCompliant", compliant);
            model.addAttribute("sensitiveDataVisible", compliant);

            if (compliant) {
                model.addAttribute("email", oidcUser.getEmail());
                model.addAttribute("subject", oidcUser.getSubject());
                model.addAttribute("claims", oidcUser.getClaims());
                model.addAttribute("idTokenClaims", oidcUser.getIdToken().getClaims());

                OidcUserInfo userInfo = oidcUser.getUserInfo();
                model.addAttribute("userInfoClaims", userInfo == null ? Collections.emptyMap() : userInfo.getClaims());

                OAuth2AuthorizedClient authorizedClient = loadAuthorizedClient(authentication);
                model.addAttribute("accessTokenClaims", extractAccessTokenClaims(authorizedClient));
                model.addAttribute("accessTokenPresent", authorizedClient != null && authorizedClient.getAccessToken() != null);
                model.addAttribute("refreshTokenPresent", authorizedClient != null && authorizedClient.getRefreshToken() != null);
            }
        } else if (authentication != null) {
            model.addAttribute("principal", authentication.getName());
            model.addAttribute("authorities", authentication.getAuthorities());
        }

        return "me";
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

    private Set<String> parseAllowedValues(String csv) {
        return java.util.Arrays.stream(csv.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .map(String::toLowerCase)
            .collect(Collectors.toCollection(HashSet::new));
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

