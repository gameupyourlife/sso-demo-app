package com.example.ssodemo.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Adds a fixed prompt value to outbound OAuth2 authorization requests.
 */
public class PromptAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver delegate;
    private final String promptValue;

    public PromptAuthorizationRequestResolver(
        ClientRegistrationRepository clientRegistrationRepository,
        String authorizationRequestBaseUri,
        String promptValue
    ) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository,
            authorizationRequestBaseUri
        );
        this.promptValue = promptValue;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return applyPrompt(delegate.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return applyPrompt(delegate.resolve(request, clientRegistrationId));
    }

    private OAuth2AuthorizationRequest applyPrompt(OAuth2AuthorizationRequest request) {
        if (request == null || !StringUtils.hasText(promptValue)) {
            return request;
        }

        Map<String, Object> additionalParameters = new LinkedHashMap<>(request.getAdditionalParameters());
        additionalParameters.put("prompt", promptValue);

        return OAuth2AuthorizationRequest.from(request)
            .additionalParameters(additionalParameters)
            .build();
    }
}

