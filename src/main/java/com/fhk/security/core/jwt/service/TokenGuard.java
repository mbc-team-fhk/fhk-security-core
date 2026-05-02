package com.fhk.security.core.jwt.service;

import io.jsonwebtoken.Claims;

public interface TokenGuard {
    void verifyAccess(Claims claims);
    void verifyRefresh(Claims claims);
}
