package com.example.ssodemo.web;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "app.sensitive-data.debug-force-compliant=true")
@AutoConfigureMockMvc
class DemoControllerDebugOverrideTrueTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void debugOverrideTrueForcesSensitiveDataVisible() throws Exception {
        mockMvc.perform(get("/me").with(oidcLogin()))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Debug override is active")))
            .andExpect(content().string(containsString("Device/session is compliant. Sensitive profile data is visible.")))
            .andExpect(content().string(containsString("Merged OIDC Claims")))
            .andExpect(content().string(containsString("ID Token Claims")))
            .andExpect(content().string(containsString("UserInfo Claims")))
            .andExpect(content().string(containsString("Access Token Claims")));
    }
}
