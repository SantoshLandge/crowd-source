package com.crowdsource.apigateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5) // Run after Spring Security (which is 0)
public class TokenRelayFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(TokenRelayFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> context.getAuthentication())
                // Only proceed if the authentication is a JWT (Resource Server validated it)
                .filter(auth -> auth instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .flatMap(jwtAuth -> {
                    Jwt jwt = jwtAuth.getToken();
                    String tokenValue = jwt.getTokenValue();

                    log.debug("Relaying EC-signed JWT for user: {}", jwt.getSubject());

                    // Mutate the request to include the Authorization header for downstream
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(request -> request
                                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokenValue)
                            )
                            .build();

                    return chain.filter(mutatedExchange);
                })
                // If no security context (e.g., public endpoints), just continue the chain
                .switchIfEmpty(chain.filter(exchange));
    }
}
