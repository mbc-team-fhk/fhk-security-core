package com.fhk.security.core.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "fhk.jwt.verifier")
public record JwtVerifierProperties(
        String publicKeyPath
) {}

/**
 * application.yaml
 *
 * fhk:
 *   jwt:
 *     verifier:
 *       public-key-path: classpath:keys/jwt-public.pem
 */