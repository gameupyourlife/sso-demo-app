package com.example.ssodemo.web;

import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class DemoControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void homeIsPublic() throws Exception {
        mockMvc.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Spring Boot SSO Demo")));
    }

    @Test
    void meRedirectsToOauthLoginWhenAnonymous() throws Exception {
        mockMvc.perform(get("/me"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", "http://localhost/oauth2/authorization/keycloak"));
    }

    @Test
    void deviceRedirectsToOauthLoginWhenAnonymous() throws Exception {
        mockMvc.perform(get("/device"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", "http://localhost/oauth2/authorization/keycloak"));
    }

    @Test
    void meIsAvailableForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/me").with(oidcLogin()))
            .andExpect(status().isOk())
            .andExpect(authenticated())
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Profile Route (/me)")));
    }

    @Test
    void oauthAuthorizationRedirectIncludesSelectAccountPrompt() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/keycloak"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("prompt=select_account")));
    }

    @Test
    void directEntraAuthorizationEndpointIsAvailable() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/entra"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("login.microsoftonline.com")))
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("prompt=select_account")));
    }

    @Test
    void entraSamlAuthenticationEndpointIsAvailable() throws Exception {
        mockMvc.perform(get("/saml2/authenticate/entra-saml"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("login.microsoftonline.com")))
            .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("SAMLRequest=")));
    }

    @Test
    void deviceRouteIsAvailableForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/device").with(oidcLogin()))
            .andExpect(status().isOk())
            .andExpect(authenticated())
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Devices Route (/device)")));
    }

    @Test
    void samlRouteIsAvailableForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/saml").with(oidcLogin()))
            .andExpect(status().isOk())
            .andExpect(authenticated())
            .andExpect(content().string(org.hamcrest.Matchers.containsString("SAML Route (/saml)")));
    }

    @Test
    void samlMetadataEndpointIsAvailable() throws Exception {
        mockMvc.perform(get("/saml2/service-provider-metadata/entra-saml"))
            .andExpect(status().isOk())
            .andExpect(content().string(org.hamcrest.Matchers.containsString("EntityDescriptor")));
    }

    @Test
    void logoutWorksWithGetLink() throws Exception {
        mockMvc.perform(get("/logout").with(oidcLogin()))
            .andExpect(status().is3xxRedirection());
    }
}

