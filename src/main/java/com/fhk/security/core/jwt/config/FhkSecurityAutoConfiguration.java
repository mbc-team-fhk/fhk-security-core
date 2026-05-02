package com.fhk.security.core.jwt.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fhk.security.core.jwt.JwtIssuer;
import com.fhk.security.core.jwt.JwtVerifier;
import com.fhk.security.core.jwt.filter.JwtAuthFilter;
import com.fhk.security.core.jwt.handler.JsonAccessDeniedHandler;
import com.fhk.security.core.jwt.handler.JsonAuthenticationEntryPoint;
import com.fhk.security.core.jwt.handler.SecurityErrorResponseWriter;
import com.fhk.security.core.jwt.service.DefaultTokenGuard;
import com.fhk.security.core.jwt.service.TokenGuard;
import com.fhk.security.core.jwt.utils.RefreshTokenHasher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.StringRedisTemplate;

@AutoConfiguration
@EnableConfigurationProperties({
        JwtIssuerProperties.class,
        JwtVerifierProperties.class,
        FhkSecurityProperties.class
})
public class FhkSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JwtIssuer.class)
    @ConditionalOnProperty(prefix = "fhk.jwt.issuer", name = "private-key-path")
    public JwtIssuer jwtIssuer(JwtIssuerProperties properties) {
        return new JwtIssuer(properties);
    }

    @Bean
    @ConditionalOnMissingBean(JwtVerifier.class)
    @ConditionalOnProperty(prefix = "fhk.jwt.verifier", name = "public-key-path")
    public JwtVerifier jwtVerifier(JwtVerifierProperties properties) {
        return new JwtVerifier(properties);
    }

    @Bean
    @ConditionalOnMissingBean(RefreshTokenHasher.class)
    public RefreshTokenHasher refreshTokenHasher() {
        return new RefreshTokenHasher();
    }

    @Bean
    @ConditionalOnMissingBean(TokenGuard.class)
    public TokenGuard tokenGuard(StringRedisTemplate redisTemplate) {
        return new DefaultTokenGuard(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthFilter.class)
    @ConditionalOnBean({JwtVerifier.class, TokenGuard.class})
    public JwtAuthFilter jwtAuthFilter(
            JwtVerifier jwtVerifier,
            TokenGuard tokenGuard,
            FhkSecurityProperties securityProperties
    ) {
        return new JwtAuthFilter(jwtVerifier, tokenGuard, securityProperties);
    }

    @Bean
    @ConditionalOnBean(JwtAuthFilter.class)
    public FilterRegistrationBean<JwtAuthFilter> jwtAuthFilterRegistration(
            JwtAuthFilter jwtAuthFilter
    ) {
        FilterRegistrationBean<JwtAuthFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(jwtAuthFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    @ConditionalOnMissingBean(SecurityErrorResponseWriter.class)
    public SecurityErrorResponseWriter securityErrorResponseWriter(
            ObjectMapper objectMapper
    ) {
        return new SecurityErrorResponseWriter(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(JsonAuthenticationEntryPoint.class)
    public JsonAuthenticationEntryPoint jsonAuthenticationEntryPoint(
            SecurityErrorResponseWriter responseWriter
    ) {
        return new JsonAuthenticationEntryPoint(responseWriter);
    }

    @Bean
    @ConditionalOnMissingBean(JsonAccessDeniedHandler.class)
    public JsonAccessDeniedHandler jsonAccessDeniedHandler(
            SecurityErrorResponseWriter responseWriter
    ) {
        return new JsonAccessDeniedHandler(responseWriter);
    }
}