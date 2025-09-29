package com.fhk.security.core.jwt;

import com.fhk.security.core.jwt.config.JwtVerifierProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

@Component
public class JwtVerifier {
    private final PublicKey publicKey;

    public JwtVerifier(JwtVerifierProperties props) {
        try {
            this.publicKey = loadPublicKey(props.publicKeyPath());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load public key", e);
        }
    }

    private PublicKey loadPublicKey(String path) throws Exception {
        byte[] keyBytes;
        if (path.startsWith("classpath:")) {
            keyBytes = Files.readAllBytes(Paths.get(
                    Objects.requireNonNull(getClass().getClassLoader()
                                    .getResource(path.substring("classpath:".length())))
                            .toURI()
            ));
        } else {
            keyBytes = Files.readAllBytes(Paths.get(path));
        }

        String keyPem = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(keyPem);

        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
    }

    public Jws<Claims> parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token);
    }

    public Claims getClaims(String token) {
        return parseToken(token).getBody();
    }
}