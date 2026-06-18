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

@SpringBootTest(properties = "app.sensitive-data.debug-force-compliant=false")
@AutoConfigureMockMvc
class DemoControllerDebugOverrideFalseTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void debugOverrideFalseForcesSensitiveDataHiddenEvenWhenClaimIsTrue() throws Exception {
        mockMvc.perform(get("/me").with(oidcLogin().idToken(token -> token.claim("device_compliant", true))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Debug override is active")))
            .andExpect(content().string(containsString("Device/session is not compliant. Sensitive data is hidden")));
    }
}

