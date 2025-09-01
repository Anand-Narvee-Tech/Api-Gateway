	package com.example.config;
	
	import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
	
	
	@Configuration
	public class SecurityConfig {
	
		@Bean
	    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
	        http
	            .csrf(ServerHttpSecurity.CsrfSpec::disable)
	            .cors(cors -> {}) // enable reactive CORS
	            .authorizeExchange(exchanges -> exchanges
	                .pathMatchers(HttpMethod.OPTIONS).permitAll()
	                .pathMatchers("/auth/**", "/customer/**").permitAll()
	                .anyExchange().authenticated()
	            );

	        return http.build();
	    }

	
		@Bean
	    public CorsWebFilter corsWebFilter() {
	        CorsConfiguration config = new CorsConfiguration();
	        config.setAllowCredentials(true);
	        config.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
	        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
	        config.setAllowedHeaders(Arrays.asList("*"));

	        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	        source.registerCorsConfiguration("/**", config);

	        return new CorsWebFilter(source);
		}	    
	}