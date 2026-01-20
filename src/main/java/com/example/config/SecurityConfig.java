package com.example.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

import com.example.authorization.PrivilegeAuthorizationManager;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Autowired
    private TJwtAuthFeignFilter jwtFilter;

    @Autowired
    private PrivilegeAuthorizationManager privilegeAuthorizationManager;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // ❌ DO NOT enable CORS here, Gateway handles it globally
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                	    .pathMatchers(HttpMethod.OPTIONS).permitAll()
                	    .pathMatchers(
                	        "/auth/**", "/auth/updated/save", "/auth/manageusers/searchAndsorting",
                	        "/bills/**",
                	        "/vendor/**", 
                	        "/customer/**",
                	        "/dashboard/**",
                	        "/manual-invoice/**",
                	        "/invoice/**"
                	    ).permitAll()
                	    .anyExchange().access(privilegeAuthorizationManager)
                	)
                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
}
