package com.example.ssodemo.config;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   LogoutSuccessHandler logoutSuccessHandler,
                                                   OAuth2AuthorizationRequestResolver authorizationRequestResolver,
                                                   @Value("${app.login.default-registration:keycloak}") String defaultRegistrationId) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/",
                    "/error",
                    "/saml",
                    "/saml2/**",
                    "/login/saml2/sso/**"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(endpoint -> endpoint
                    .authorizationRequestResolver(authorizationRequestResolver)
                )
            )
            .saml2Login(saml2 -> saml2
                .failureHandler((request, response, exception) -> {
                    String encodedMessage = URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8);
                    response.sendRedirect("/saml?samlError=" + encodedMessage);
                })
            )
            .saml2Metadata(Customizer.withDefaults())
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/" + defaultRegistrationId))
            )
            .logout(logout -> logout
                .logoutRequestMatcher(new OrRequestMatcher(
                    new AntPathRequestMatcher("/logout", "GET"),
                    new AntPathRequestMatcher("/logout", "POST")
                ))
                .logoutSuccessHandler((request, response, authentication) -> {
                    try {
                        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
                    } catch (Exception exception) {
                        // Fallback keeps logout route usable even if provider-initiated logout fails.
                        response.sendRedirect("/");
                    }
                })
            );

        return http.build();
    }


    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler handler =
            new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("{baseUrl}/");
        return handler;
    }

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
        ClientRegistrationRepository clientRegistrationRepository,
        @Value("${app.login.prompt:select_account}") String promptValue
    ) {
        return new PromptAuthorizationRequestResolver(
            clientRegistrationRepository,
            "/oauth2/authorization",
            promptValue
        );
    }
}
