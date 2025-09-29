package com.fhk.security.core.jwt.filter;

import com.fhk.security.core.interfaces.TokenGuard;
import com.fhk.security.core.jwt.JwtVerifier;
import com.fhk.security.core.jwt.config.DefaultWhiteList;
import com.fhk.security.core.record.FhkUserPrincipal;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtVerifier jwtVerifier;      // 비대칭 키 public 으로 인증 적용
    private final TokenGuard tokenGuard;        // interface 확인. 각 서버에서 구현

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String method = request.getMethod();

        return DefaultWhiteList.URIS.stream().anyMatch(pattern -> {
            if (pattern.contains(":")) {
                String[] parts = pattern.split(":");
                return method.equalsIgnoreCase(parts[1]) && uri.startsWith(parts[0]);
            }
            return uri.startsWith(pattern);
        });
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        log.info("jwt auth filter in...");

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
        String HEADER_STRING = "Authorization";
        String TOKEN_PREFIX = "Bearer ";

        var header = req.getHeader(HEADER_STRING);
        log.info(header);
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

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