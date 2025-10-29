

//    @Bean
//    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
//        return http
//                .csrf(ServerHttpSecurity.CsrfSpec::disable)
//                .cors(cors -> {}) // handled via CorsWebFilter
//                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
//                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
//                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
//                .authorizeExchange(exchanges -> exchanges
//                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
//                        .pathMatchers("/auth/login", "/auth/register",
//                                      "/auth/login/send-otp", "/auth/check-token",
//                                      "/auth/validate-token").permitAll()
//                        .pathMatchers("/auth/manageusers/**").hasAnyRole("SUPERADMIN", "ADMIN")
//                        .pathMatchers("/customer/**", "/vendor/**", "/invoice/**",
//                                      "/manual-invoice/**", "/bills/**")
//                        .hasAnyRole("ADMIN", "ACCOUNTANT", "DEVELOPER")
//                        .anyExchange().authenticated()
//                )
//                // Add your reactive JWT filter at the AUTHENTICATION step
//                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
//                .build();
//    }
    
//    @Bean
//    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
//        return http
//                .csrf(ServerHttpSecurity.CsrfSpec::disable)
//                .cors(cors -> {})
//                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
//                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
//                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
//                .authorizeExchange(exchanges -> exchanges
//                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
//                        .pathMatchers("/auth/login", "/auth/register",
//                                      "/auth/login/send-otp", "/auth/check-token",
//                                      "/auth/validate-token").permitAll()
//                        .pathMatchers("/auth/manageusers/**","/auth/**").hasAnyRole("SUPERADMIN", "ADMIN")
//                        .pathMatchers("/customer/**", "/vendor/**", "/invoice/**",
//                        		"/manual-invoice/**", "/bills/**")
//                        .hasAnyRole("ADMIN", "ACCOUNTANT", "DEVELOPER")
//                        .anyExchange().authenticated()
//                )
//                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
//                .build();
//    }

 package com.example.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.example.authorization.PrivilegeAuthorizationManager;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {


	
//	 @Bean
//	    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
//	        http
//	            .csrf(ServerHttpSecurity.CsrfSpec::disable)
//	            .cors().and()  // use global CORS config from properties
//	            .authorizeExchange(exchanges -> exchanges
//	                .pathMatchers(HttpMethod.OPTIONS).permitAll()
//	                .pathMatchers("/auth/**", "/customer/**", "/vendor/**", "/invoice/**").permitAll()
//	                .anyExchange().authenticated()
//	            );
//	        return http.build();
//	    }
//	
	
	@Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
     http
   .csrf(ServerHttpSecurity.CsrfSpec::disable)
           .cors(cors -> {})  // just enable, do not configure here
           .authorizeExchange(exchanges -> exchanges
           .pathMatchers(HttpMethod.OPTIONS).permitAll()
           .pathMatchers("/auth/**", "/customer/**","/vendor/**", "/invoice/**", "/manual-invoice/**" , "/bills/**").permitAll()
           .anyExchange().authenticated());
 return http.build();
}

    @Autowired
    private TJwtAuthFeignFilter jwtFilter;
    
    @Autowired
    private PrivilegeAuthorizationManager privilegeAuthorizationManager;


    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> {})
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        // Allow preflight requests
                        .pathMatchers(HttpMethod.OPTIONS).permitAll()
                        // Public endpoints (login, register, OTP, token check)
                        .pathMatchers("/auth/login", "/auth/register",
                                      "/auth/login/send-otp", "/auth/check-token",
                                      "/auth/validate-token","/auth/roles/**", 
                                      "/auth/privileges/**","/bills/**","/vendor/**",  "/customer/**", "/manual-invoice/**", "/invoice/**").permitAll()
                        // All other endpoints → dynamic privilege check
                        .anyExchange().access(privilegeAuthorizationManager)
                )
                // JWT filter → extract roles & privileges
                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of("http://localhost:4200", "http://10.10.0.200:4200"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        config.setExposedHeaders(List.of("Authorization", "Content-Disposition"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}
