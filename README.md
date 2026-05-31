# fhk-security-core

FHK 서비스들이 공통으로 사용하는 인증 정책 모듈입니다. 단독 실행 애플리케이션이 아니라 다른 Spring Boot 서비스에 포함되는 `java-library` 모듈입니다.

## Purpose

- JWT 발급과 검증 로직 공통화
- Spring Security JWT filter 공통화
- 인증 실패/인가 실패 JSON 응답 공통화
- token version 검증을 위한 `TokenGuard` 추상화
- whitelist 기반 JWT filter skip 정책 제공

## Provides

- `JwtIssuer`: RSA private key 기반 access/refresh token 발급
- `JwtVerifier`: RSA public key 기반 JWT 검증
- `JwtAuthFilter`: Bearer token 검증 후 `SecurityContext` 주입
- `DefaultTokenGuard`: Redis 기반 access/refresh token version 검증
- `JsonAuthenticationEntryPoint`, `JsonAccessDeniedHandler`: JSON 보안 오류 응답
- `FhkSecurityAutoConfiguration`: Spring Boot auto-configuration

## Used By

- [fhk-security-server](https://github.com/mbc-team-fhk/fhk-security-server)
- [fhk-ticket-reservation](https://github.com/mbc-team-fhk/fhk-ticket-reservation)

## Usage

현재 repo들은 배포된 Maven package 대신 빌드된 jar를 `libs/`에 두고 참조합니다.

```gradle
implementation files("libs/fhk-security-core-1.0.0-plain.jar")
```

JWT key path와 whitelist는 각 서비스의 `application.yaml`에서 설정합니다.

```yaml
fhk:
  security:
    whitelist:
      - OPTIONS:/**
      - /actuator/health
  jwt:
    verifier:
      public-key-path: classpath:keys/jwt-public.pem
```
