package com.example.client;

import java.util.Map;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "INVOICE-LOGIN-SERVICE", url = "${login.service.url}")
public interface LoginServiceFeign {

    @PostMapping("/auth/validate-token")
    Map<String, Object> validateToken(@RequestHeader("Authorization") String authHeader);
    
    @GetMapping("/auth/check-token")
    Map<String, Object> checkToken(@RequestParam("token") String token);
    
    @GetMapping("/auth/privileges/access/endpoint-privileges")
    Map<String, String> getEndpointPrivilegeMap();
}