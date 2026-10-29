package com.crowdsource.apigateway.config;

import org.springframework.http.HttpCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Resolves the access token for the resource-server filter.
 * <ol>
 *   <li>Public endpoints (login, signup, refresh, logout) are never authenticated. Without this an
 *       expired {@code access_token} cookie would make {@code /refresh} fail with 401 - exactly the
 *       moment the client needs it.</li>
 *   <li>The HttpOnly {@code access_token} cookie (browser clients).</li>
 *   <li>Fallback: standard {@code Authorization: Bearer ...} header (Postman, mobile, other services).</li>
 * </ol>
 */
public class CookieBearerTokenConverter implements ServerAuthenticationConverter {

    public static final String ACCESS_TOKEN_COOKIE = "access_token";

    private final Set<String> publicPaths;
    private final ServerBearerTokenAuthenticationConverter headerConverter = new ServerBearerTokenAuthenticationConverter();

    public CookieBearerTokenConverter(Set<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        if (publicPaths.contains(path)) {
            return Mono.empty();
        }

        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(ACCESS_TOKEN_COOKIE);
        if (cookie != null && StringUtils.hasText(cookie.getValue())) {
            return Mono.just(new BearerTokenAuthenticationToken(cookie.getValue()));
        }
        return headerConverter.convert(exchange);
    }
}
