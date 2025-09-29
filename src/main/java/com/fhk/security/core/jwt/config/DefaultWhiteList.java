package com.fhk.security.core.jwt.config;

import java.util.List;

public class DefaultWhiteList {
    public static final List<String> URIS = List.of(
            "/v3/api-docs/**",
            "/swagger-ui.html",
            "/swagger-ui/**"
    );
}
