package com.fhk.security.core.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt.verifier")
public record JwtVerifierProperties(
        String publicKeyPath
) {}

