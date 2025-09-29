package com.fhk.security.core.record;

import java.security.Principal;

public record FhkUserPrincipal(Long id, String role, Long version) implements Principal {
    @Override
    public String getName() {
        return String.valueOf(id);
    }
}