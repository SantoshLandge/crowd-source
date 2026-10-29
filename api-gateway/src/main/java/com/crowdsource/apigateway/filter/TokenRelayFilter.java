package com.crowdsource.apigateway.filter;

import com.crowdsource.apigateway.config.CookieBearerTokenConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Relays the validated identity to downstream services.
 * <ul>
 *   <li>ALWAYS strips any client-supplied identity headers first (anti-spoofing), also on public routes.</li>
 *   <li>For authenticated requests sets X-User-Id / X-User-Name / X-User-Authorities plus a timestamp and an
 *       HMAC-SHA256 signature so downstream services can verify the headers really came from the gateway.</li>
 *   <li>Does not leak the JWT downstream: the Authorization header and the access_token cookie are removed.</li>
 * </ul>
 * The signature format must stay identical to {@code GatewaySignature} in security-shared-utility.
 */
@Component
public class TokenRelayFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(TokenRelayFilter.class);

    static final String USER_ID = "X-User-Id";
    static final String USER_NAME = "X-User-Name";
    static final String AUTHORITIES = "X-User-Authorities";
    static final String TIMESTAMP = "X-Gateway-Timestamp";
    static final String SIGNATURE = "X-Gateway-Signature";
    private static final List<String> IDENTITY_HEADERS = List.of(USER_ID, USER_NAME, AUTHORITIES, TIMESTAMP, SIGNATURE);

    private static final String HMAC = "HmacSHA256";

    private final String secret;

    public TokenRelayFilter(@Value("${app.security.gateway-secret}") String secret) {
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException("app.security.gateway-secret must be at least 32 characters");
        }
        this.secret = secret;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())          // anonymous / public route -> still continue exactly ONCE
                .flatMap(maybeAuth -> {
                    if (maybeAuth.isEmpty()) {
                        return chain.filter(forwardAnonymous(exchange));
                    }
                    ServerWebExchange mutated = forwardAuthenticated(exchange, maybeAuth.get());
                    if (mutated == null) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    return chain.filter(mutated);
                });
    }

    private ServerWebExchange forwardAnonymous(ServerWebExchange exchange) {
        return exchange.mutate()
                .request(request -> request.headers(this::stripSensitive))
                .build();
    }

    /** @return the mutated exchange, or null when the token carries no usable user id. */
    private ServerWebExchange forwardAuthenticated(ServerWebExchange exchange, JwtAuthenticationToken jwtAuth) {
        Jwt jwt = jwtAuth.getToken();

        Object userIdClaim = jwt.getClaim("userId");
        if (userIdClaim == null || String.valueOf(userIdClaim).isBlank()) {
            log.warn("JWT for subject {} has no userId claim - rejecting", jwt.getSubject());
            return null;
        }
        String userId = String.valueOf(userIdClaim);
        String username = jwt.getClaimAsString("username") != null ? jwt.getClaimAsString("username") : jwt.getSubject();
        String authorities = jwtAuth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long timestamp = System.currentTimeMillis();
        String signature = sign(userId, username, authorities, timestamp);

        log.debug("Forwarding identity userId={} username={} authorities={}", userId, username, authorities);

        return exchange.mutate()
                .request(request -> request.headers(headers -> {
                    stripSensitive(headers);
                    headers.set(USER_ID, userId);                 // set(), never add(): no duplicated values
                    headers.set(USER_NAME, username);
                    headers.set(AUTHORITIES, authorities);
                    headers.set(TIMESTAMP, String.valueOf(timestamp));
                    headers.set(SIGNATURE, signature);
                }))
                .build();
    }

    /** Removes spoofable identity headers and the credentials the downstream services never need. */
    private void stripSensitive(HttpHeaders headers) {
        IDENTITY_HEADERS.forEach(name -> headers.remove(name));
        headers.remove(HttpHeaders.AUTHORIZATION);

        List<String> cookieHeaders = headers.get(HttpHeaders.COOKIE);
        if (cookieHeaders != null) {
            String remaining = cookieHeaders.stream()
                    .flatMap(line -> Arrays.stream(line.split(";")))
                    .map(String::trim)
                    .filter(c -> !c.isEmpty() && !c.startsWith(CookieBearerTokenConverter.ACCESS_TOKEN_COOKIE + "="))
                    .collect(Collectors.joining("; "));
            if (remaining.isEmpty()) {
                headers.remove(HttpHeaders.COOKIE);
            } else {
                headers.set(HttpHeaders.COOKIE, remaining);   // keeps refresh_token for /auth/v1/refresh|logout
            }
        }
    }

    private String sign(String userId, String username, String authorities, long timestamp) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC));
            String canonical = userId + "\n" + username + "\n" + authorities + "\n" + timestamp;
            return HexFormat.of().formatHex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to sign gateway headers", e);
        }
    }

    @Override
    public int getOrder() {
        // Must run BEFORE the routing filters. Ordered.LOWEST_PRECEDENCE (the previous value) ties with
        // NettyRoutingFilter, i.e. the headers could be added after the request was already sent.
        return -1;
    }
}
