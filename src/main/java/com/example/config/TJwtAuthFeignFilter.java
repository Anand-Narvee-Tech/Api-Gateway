package com.example.config;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class TJwtAuthFeignFilter implements WebFilter {

    @Value("${jwt.secret}")
    private String secret;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();

        // ✅ Skip public endpoints & OPTIONS requests
        if (path.startsWith("/auth/login")
            || path.startsWith("/auth/register")
            || path.startsWith("/auth/login/send-otp")
            || path.startsWith("/auth/check-token")
            || path.startsWith("/auth/validate-token")
            || path.startsWith("/auth/roles/")
            || path.startsWith("/auth/privileges/")
            || path.startsWith("/vendor/")
            || path.startsWith("/customer/")
            || path.startsWith("/manual-invoice/")
            || path.startsWith("/invoice/")
            || path.startsWith("/bills/")
            || exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        // ✅ Validate Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7).trim();

        return Mono.fromCallable(() -> {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            if (username == null)
                throw new RuntimeException("JWT missing subject");

            List<SimpleGrantedAuthority> authorities = new ArrayList<>();

            List<String> roles = claims.get("roles", List.class);
            if (roles != null)
                roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase())));

            List<String> privileges = claims.get("privileges", List.class);
            if (privileges != null)
                privileges.forEach(p -> authorities.add(new SimpleGrantedAuthority(p.toUpperCase())));

            log.info("✅ Authenticated user: {} with authorities: {}", username, authorities);

            return new UsernamePasswordAuthenticationToken(username, null, authorities);
        })
        .flatMap(auth -> chain.filter(exchange)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth)))
        .onErrorResume(e -> {
            log.error("❌ JWT validation failed: {}", e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        });
    }
}