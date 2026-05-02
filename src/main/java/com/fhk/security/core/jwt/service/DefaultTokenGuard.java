package com.fhk.security.core.jwt.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;

import java.util.Date;

@RequiredArgsConstructor
public class DefaultTokenGuard implements TokenGuard {

    private final StringRedisTemplate redisTemplate;

    @Override
    public void verifyAccess(Claims claims) {
        verifyCommon(claims, "access");
    }

    @Override
    public void verifyRefresh(Claims claims) {
        verifyCommon(claims, "refresh");
    }

    private void verifyCommon(Claims claims, String expectedAudience) {
        long uid = parseUid(claims);
        Integer tokenVersion = claims.get("version", Integer.class);

        if (claims.getAudience() == null || !claims.getAudience().contains(expectedAudience)) {
            throw new BadCredentialsException("not " + expectedAudience + " token");
        }

        Date expDate = claims.getExpiration();
        if (expDate == null) {
            throw new BadCredentialsException("exp missing");
        }

        checkVersion(uid, tokenVersion);
    }

    private long parseUid(Claims claims) {
        try {
            return Long.parseLong(claims.getSubject());
        } catch (Exception e) {
            throw new BadCredentialsException("invalid subject");
        }
    }

    private void checkVersion(long uid, Integer tokenVersion) {
        String redisKey = "fhk:security:account:" + uid + ":ver";
        String redisValue = redisTemplate.opsForValue().get(redisKey);

        if (redisValue == null) {
            throw new CredentialsExpiredException("no version info in cache");
        }

        int currentVersion;
        try {
            currentVersion = Integer.parseInt(redisValue);
        } catch (NumberFormatException e) {
            throw new CredentialsExpiredException("invalid version info in cache");
        }

        if (tokenVersion == null || !tokenVersion.equals(currentVersion)) {
            throw new CredentialsExpiredException("ver mismatch");
        }
    }
}
