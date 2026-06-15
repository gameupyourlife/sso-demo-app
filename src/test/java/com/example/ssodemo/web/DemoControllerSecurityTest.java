package com.example.ssodemo.web;

import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
            .andExpect(status().isOk());
    }

    @Test
    void meRedirectsToOauthLoginWhenAnonymous() throws Exception {
        mockMvc.perform(get("/me"))
            .andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location", "http://localhost/oauth2/authorization/keycloak"));
    }

    @Test
    void meIsAvailableForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/me").with(oidcLogin()))
            .andExpect(status().isOk())
            .andExpect(authenticated());
    }
}

