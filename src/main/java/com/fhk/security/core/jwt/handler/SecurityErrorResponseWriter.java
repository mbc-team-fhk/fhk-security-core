package com.fhk.security.core.jwt.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fhk.common.api.ApiResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

@RequiredArgsConstructor
public class SecurityErrorResponseWriter {

    private final ObjectMapper objectMapper;

    public void writeUnauthorized(
            HttpServletResponse response,
            String message
    ) throws IOException {

        if (response.isCommitted()) {
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json;charset=UTF-8");

        var body = ApiResponse.error(
                HttpServletResponse.SC_UNAUTHORIZED,
                message
        ).getBody();

        objectMapper.writeValue(response.getWriter(), body);
    }

    public void writeForbidden(
            HttpServletResponse response,
            String message
    ) throws IOException {

        if (response.isCommitted()) {
            return;
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=UTF-8");

        var body = ApiResponse.error(
                HttpServletResponse.SC_FORBIDDEN,
                message
        ).getBody();

        objectMapper.writeValue(response.getWriter(), body);
    }
}