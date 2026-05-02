package com.fhk.security.core.jwt;

import com.fhk.security.core.jwt.config.JwtIssuerProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

@Component
public class JwtIssuer {
    private final PrivateKey privateKey;
    private final long accessExpireMs;
    private final long refreshExpireMs;

    public JwtIssuer(JwtIssuerProperties props) {
        try {
            this.privateKey = loadPrivateKey(props.privateKeyPath());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load private key", e);
        }
        this.accessExpireMs = props.accessExpireMs();
        this.refreshExpireMs = props.refreshExpireMs();
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] keyBytes;

        if (path.startsWith("classpath:")) {
            keyBytes = Files.readAllBytes(Paths.get(
                    Objects.requireNonNull(getClass().getClassLoader().getResource(path.substring("classpath:".length()))).toURI()
            ));
        } else {
            keyBytes = Files.readAllBytes(Paths.get(path));
        }

        String keyPem = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        var decoded = Base64.getDecoder().decode(keyPem);
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    public String issueAccessToken(Long userId, String role, Long ver) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("role", role)
                .claim("version", ver)

                .id(UUID.randomUUID().toString())
                .audience().add("access").and()
                .issuedAt(new Date(now))
                .expiration(new Date(now + accessExpireMs))

                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public String issueRefreshToken(Long userId, Long ver) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("version", ver)

                .id(UUID.randomUUID().toString())
                .audience().add("refresh").and()
                .issuedAt(new Date(now))
                .expiration(new Date(now + refreshExpireMs))

                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }
}
