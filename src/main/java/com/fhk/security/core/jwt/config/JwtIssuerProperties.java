package com.fhk.security.core.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt.issuer")
public record JwtIssuerProperties(
        String privateKeyPath,
        long accessExpireMs,
        long refreshExpireMs
) {}

