package com.fhk.security.core.jwt.filter;

import com.fhk.security.core.jwt.config.FhkSecurityProperties;
import com.fhk.security.core.jwt.service.TokenGuard;
import com.fhk.security.core.jwt.JwtVerifier;
import com.fhk.security.core.record.FhkUserPrincipal;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.PathContainer;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtVerifier jwtVerifier;                      // 비대칭 키 public 으로 인증 적용
    private final TokenGuard tokenGuard;                        // interface 확인. 각 서버에서 구현
    private final FhkSecurityProperties securityProperties;     // 화이트리스트 skip 처리

    private final PathPatternParser pathPatternParser = new PathPatternParser();
    private final Map<String, PathPattern> pathPatternCache = new ConcurrentHashMap<>();

    private static final String HEADER_STRING = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";

    private String maskBearerToken(String header) {
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            return "none";
        }

        String token = header.substring(TOKEN_PREFIX.length());

        if (token.length() <= 12) {
            return TOKEN_PREFIX + "****";
        }

        return TOKEN_PREFIX + token.substring(0, 8) + "...****..." + token.substring(token.length() - 4);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        boolean skip = securityProperties.getWhitelist().stream()
                .anyMatch(white -> matches(request, white));

        if (skip) {
            log.debug("shouldNotFilter() skip. requestHash={}, method={}, uri={}",
                    System.identityHashCode(request),
                    request.getMethod(), request.getRequestURI());
        }

        return skip;
    }

    private boolean matches(HttpServletRequest request, String white) {
        String requestMethod = request.getMethod();
        String requestPath = request.getRequestURI();

        if (white.contains(":")) {
            String[] parts = white.split(":", 2);
            String method = parts[0];
            String pattern = parts[1];

            return requestMethod.equalsIgnoreCase(method)
                    && matchPath(pattern, requestPath);
        }

        return matchPath(white, requestPath);
    }

    private boolean matchPath(String pattern, String requestPath) {
        PathPattern pathPattern = pathPatternCache.computeIfAbsent(
                pattern,
                pathPatternParser::parse
        );

        return pathPattern.matches(PathContainer.parsePath(requestPath));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        // CORS 등 preflight 요청은 JWT 인증 skip
        if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(req, res);
            return;
        }

        // 다른 Filter 에서 상위 인증을 통해 SecurityContext 가 이미 주입된 경우 JWT 인증 skip
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(req, res);
            return;
        }

        // 헤더가 Authorization Bearer 가 아닌경우 JWT 인증 skip
        // 그냥 skip 시켜도 이후 authorizeHttpRequests 단계에서 EntryPoint 를 통해 미인증 보호 API 요청에 401 리턴
        var header = req.getHeader(HEADER_STRING);
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        log.debug("doFilterInternal() in.");
        log.debug("doFilterInternal() requestHash={}", System.identityHashCode(req));
        log.debug("doFilterInternal() header={}", maskBearerToken(header));
        log.debug("doFilterInternal() method={}, uri={}", req.getMethod(), req.getRequestURI());


        // 토큰 인증 로직
        // Access 토큰 검증은  컨트롤러로 넘기지 말것.  redis 캐시 DB 등을 사용해 필터 내에서 검증 끝낼것.
        // 임시 처리로 일단 TokenGuard -> DB 넘김 +++++
        var token = header.substring(TOKEN_PREFIX.length());

        try {
            var claims = jwtVerifier.getClaims(token);
            tokenGuard.verifyAccess(claims); // Redis/DB 상태 검증

            Long userId = Long.valueOf(claims.getSubject());
            String role = claims.get("role", String.class);
            Long version = claims.get("version", Long.class);

            var principal = new FhkUserPrincipal(userId, role, version);
            var authorities = AuthorityUtils.createAuthorityList("ROLE_" + role);

            // Token 인증 기반은 credentials 필요 없음 -> null 처리
            var auth = new UsernamePasswordAuthenticationToken(principal, null, authorities);
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

            // 해당 endpoint 요청에 대한 Security Context 유지 설정
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(auth);
            SecurityContextHolder.setContext(context);

            // 해당 endpoint 요청에 대한 Security Context 유지 설정 type 2
            // SecurityContextHolder.getContext().setAuthentication(auth);

            chain.doFilter(req, res);

        } catch (ResponseStatusException e) {
            log.info("token error: {}", e.getReason());
            res.sendError(e.getStatusCode().value(), e.getReason());

        } catch (JwtException ex) { // io.jsonwebtoken 계열
            log.info(ex.getMessage());
            log.info("Invalid or expired token: {}", ex.getMessage());
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
        }
    }
}