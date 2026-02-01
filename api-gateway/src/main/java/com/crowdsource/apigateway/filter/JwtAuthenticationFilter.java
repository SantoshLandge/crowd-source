package com.crowdsource.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Set;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final SecretKey secretKey;

    // Public endpoints (NO JWT required)
    private static final Set<String> PUBLIC_ENDPOINTS = Set.of(
            "/api/auth/signup",
            "/api/auth/login",
            "/h2-console"
    );

    public JwtAuthenticationFilter(@Value("${app.jwt.secret}") String secret) {
        super(Config.class);
        log.info("🔧 JwtAuthenticationFilter initialized with {} public endpoints", PUBLIC_ENDPOINTS.size());
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Log incoming request
            String requestPath = exchange.getRequest().getPath().toString();
            String method = exchange.getRequest().getMethod().name();
            log.debug("🌐 [{}] {} - Request received", method, requestPath);

            // Skip auth for public endpoints
            if (isPublicEndpoint(requestPath)) {
                log.debug("✅ {} {} - Public endpoint, skipping JWT validation", method, requestPath);
                return chain.filter(exchange);
            }

            log.debug("🔍 {} {} - Private endpoint, validating JWT...", method, requestPath);

            // Extract & validate JWT
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

            if (authHeader == null) {
                log.warn("❌ {} {} - Missing Authorization header", method, requestPath);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            if (!authHeader.startsWith("Bearer ")) {
                log.warn("❌ {} {} - Invalid Authorization format: {}", method, requestPath, authHeader);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String jwtToken = authHeader.substring(7);
            log.debug("🔍 {} {} - Extracted JWT token (length: {})", method, requestPath, jwtToken.length());

            try {
                // Parse & validate JWT
                Claims claims = Jwts.parser()
                        .verifyWith(secretKey)
                        .build()
                        .parseSignedClaims(jwtToken)
                        .getPayload();

                String userId = claims.getSubject();
                Object rolesObj = claims.get("roles");
                String email = claims.get("email", String.class);

                log.info("✅ {} {} - JWT validated: userId={}, roles={}", method, requestPath, userId, rolesObj);

                // Add user context headers for downstream services
                exchange.getRequest().mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Roles", convertRolesToString(rolesObj))
                        .header("X-User-Email", email != null ? email : "")
                        .build();

                log.debug("🔄 {} {} - Forwarding to downstream service with user headers", method, requestPath);

                // Continue filter chain (route to service)
                return chain.filter(exchange);

            } catch (Exception e) {
                log.error("❌ {} {} - JWT validation failed: {}", method, requestPath, e.getMessage(), e);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                exchange.getResponse().getHeaders().add("WWW-Authenticate", "Bearer error=\"invalid_token\"");
                return exchange.getResponse().setComplete();
            }
        };
    }

    private boolean isPublicEndpoint(String path) {
        return PUBLIC_ENDPOINTS.stream().anyMatch(path::startsWith);
    }

    // roles conversion method
    private String convertRolesToString(Object rolesObj) {
        if (rolesObj == null) return "[]";

        try {
            if (rolesObj instanceof String) {
                return (String) rolesObj;
            } else if (rolesObj instanceof java.util.List) {
                // Convert ArrayList<String> → "ROLE_USER,ROLE_ADMIN"
                return ((java.util.List<?>) rolesObj).stream()
                        .map(Object::toString)
                        .collect(java.util.stream.Collectors.joining(","));
            } else {
                // Fallback: toString()
                return rolesObj.toString();
            }
        } catch (Exception e) {
            log.warn("Failed to convert roles: {}", e.getMessage());
            return "[]";
        }
    }

    /**
     * Spring Cloud Gateway REQUIRED config class (even if empty)
     * Enables YAML configuration in the future: filters: - name: JwtAuthFilter args: {...}
     */
    public static class Config {
        // Future: List<String> publicPaths;
        // Future: boolean enabled;
    }
}