package com.crowdsource.apigateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.stream.Collectors;

@Component
public class TokenRelayFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(TokenRelayFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .flatMap(jwtAuth -> {
                    Jwt jwt = jwtAuth.getToken();

                    // Extract values out of the validated JWT context
                    // Safely extract username & userId
                    String username = jwt.getClaimAsString("username") != null ?
                            jwt.getClaimAsString("username") : jwt.getSubject();

                    Object userIdClaim = jwt.getClaim("userId");
                    String userId = userIdClaim != null ? String.valueOf(userIdClaim) : "";

                    // Safely extract authorities
                    String authorities = jwtAuth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.joining(","));

                    log.debug("Successfully identified user: {}, ID: {}, Roles: {}. Forwarding headers downstream.",
                            username, userId, authorities);

                    // Inject the plain text headers into the outgoing downstream request
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(builder -> builder
                                    .header("X-User-Id", userId)
                                    .header("X-User-Name", username)
                                    .header("X-User-Authorities", authorities)
                            )
                            .build();

                    return chain.filter(mutatedExchange);
                })
                // Fallback for public routes
                .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        // Crucial: Runs immediately after the security context layer resolves routing parameters
        return Ordered.LOWEST_PRECEDENCE;
    }
}
