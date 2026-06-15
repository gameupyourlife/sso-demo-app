package com.example.ssodemo.web;

import java.time.Instant;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;

@Controller
public class DemoController {

    @GetMapping("/")
    public String home(Authentication authentication, Model model) {
        model.addAttribute("app", "sso-demo-app");
        model.addAttribute("now", Instant.now().toString());
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("login", "/oauth2/authorization/keycloak");
        model.addAttribute("profile", "/me");
        model.addAttribute("logout", "/logout");
        model.addAttribute("message", "Login happens against Keycloak, and Keycloak can federate to Microsoft Entra ID.");
        return "home";
    }

    @GetMapping("/me")
    public String me(Authentication authentication, Model model) {
        model.addAttribute("authenticated", authentication != null && authentication.isAuthenticated());
        model.addAttribute("logout", "/logout");
        model.addAttribute("home", "/");

        if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
            model.addAttribute("name", oidcUser.getFullName());
            model.addAttribute("preferredUsername", oidcUser.getPreferredUsername());
            model.addAttribute("email", oidcUser.getEmail());
            model.addAttribute("subject", oidcUser.getSubject());
            model.addAttribute("issuer", oidcUser.getIssuer());
            model.addAttribute("claims", oidcUser.getClaims());
        } else if (authentication != null) {
            model.addAttribute("principal", authentication.getName());
            model.addAttribute("authorities", authentication.getAuthorities());
        }

        return "me";
    }
}


