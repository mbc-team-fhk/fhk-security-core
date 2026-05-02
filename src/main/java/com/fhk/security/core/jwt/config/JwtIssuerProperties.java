package com.fhk.security.core.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "fhk.jwt.issuer")
public record JwtIssuerProperties(
        String privateKeyPath,
        long accessExpireMs,
        long refreshExpireMs
) {}

/**
 * application.yaml
 *
 * fhk:
 *   jwt:
 *     issuer:
 *       private-key-path: classpath:keys/jwt-private.pem
 *       access-expire-ms: 900000       # 15분
 *       refresh-expire-ms: 1209600000   # 14일
 */