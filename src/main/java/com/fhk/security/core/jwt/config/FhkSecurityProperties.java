package com.fhk.security.core.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "fhk.security")
public class FhkSecurityProperties {

    private List<String> whitelist = new ArrayList<>();

    public List<String> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<String> whitelist) {
        this.whitelist = whitelist;
    }
}

/**
 * application.yaml
 *
 * fhk:
 *   security:
 *     whitelist:
 *       - OPTIONS:/**
 *       - /actuator/health
 *       - /actuator/health/**
 *       - /actuator/info
 *       - /swagger-ui/**
 *       - /swagger-ui.html
 *       - /v3/api-docs/**
 *       - POST:/auth/login
 *       - POST:/auth/refresh
 *       - POST:/accounts
 *       - GET:/accounts/availability
 */