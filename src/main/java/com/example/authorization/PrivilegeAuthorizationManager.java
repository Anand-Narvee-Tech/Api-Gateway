package com.example.authorization;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;

import com.example.client.LoginServiceFeign;

import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class PrivilegeAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private final LoginServiceFeign loginServiceFeign; // Feign client to fetch privileges
    private Map<String, String> endpointPrivileges = new ConcurrentHashMap<>();

    @Autowired
    public PrivilegeAuthorizationManager(LoginServiceFeign loginServiceFeign) {
        this.loginServiceFeign = loginServiceFeign;
        refreshPrivilegeMap(); // Load initially
    }

    // Refresh privilege map every 5 minutes
    @Scheduled(fixedDelay = 300000)
    public void refreshPrivilegeMap() {
        try {
            endpointPrivileges = loginServiceFeign.getEndpointPrivilegeMap();
            log.info("Loaded {} endpoint privilege mappings", endpointPrivileges.size());
        } catch (Exception e) {
            log.error("⚠️ Failed to refresh privilege mappings: {}", e.getMessage());
        }
    }

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context) {
        String path = context.getExchange().getRequest().getPath().toString();
        String requiredPrivilege = getRequiredPrivilege(path);

        // If no privilege mapping exists for this endpoint, deny access
        if (requiredPrivilege == null) {
            log.warn("No privilege mapping found for path '{}'. Denying access.", path);
            return Mono.just(new AuthorizationDecision(false));
        }

        return authentication.map(auth -> {
            boolean granted = auth.getAuthorities().stream()
                    .map(a -> a.getAuthority())
                    .anyMatch(a -> a.equalsIgnoreCase(requiredPrivilege)); // Only match selected privilege

            log.info("[{}] requires '{}', granted={}", path, requiredPrivilege, granted);
            return new AuthorizationDecision(granted);
        }).defaultIfEmpty(new AuthorizationDecision(false)); // No authentication → deny
    }

    private String getRequiredPrivilege(String path) {
        // Find first endpoint that matches the request path
        return endpointPrivileges.entrySet().stream()
                .filter(entry -> path.startsWith(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }
}