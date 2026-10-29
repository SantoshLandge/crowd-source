package com.crowdsource.security.shared.filter;

import com.crowdsource.security.shared.model.GatewayHeaders;
import com.crowdsource.security.shared.model.GatewaySignature;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

/**
 * Turns the identity headers injected by the API gateway into a Spring Security
 * {@link org.springframework.security.core.Authentication}.
 * <p>
 * Contract exposed to controllers/services:
 * <ul>
 *   <li>{@code authentication.getPrincipal()} / {@code getName()} -> user id (String)</li>
 *   <li>{@code authentication.getDetails()} -> username / e-mail (String)</li>
 *   <li>{@code authentication.getAuthorities()} -> roles ({@code ROLE_*}) and permissions</li>
 * </ul>
 * <p>
 * Security rules:
 * <ul>
 *   <li>No identity headers -> request continues anonymously (the authorization rules decide).</li>
 *   <li>Identity headers present but signature missing / invalid / stale -> 401, never trusted.</li>
 * </ul>
 * This class is intentionally NOT a Spring bean: if it were, Spring Boot would also register it as a
 * servlet filter and, being a {@link OncePerRequestFilter}, it would then be skipped inside the
 * security filter chain where it is actually needed.
 */
public class SharedGatewayHeaderFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SharedGatewayHeaderFilter.class);

    private final String secret;
    private final Duration maxClockSkew;
    private final AuthenticationEntryPoint entryPoint;

    public SharedGatewayHeaderFilter(String secret, Duration maxClockSkew, AuthenticationEntryPoint entryPoint) {
        this.secret = secret;
        this.maxClockSkew = maxClockSkew;
        this.entryPoint = entryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String userId = request.getHeader(GatewayHeaders.USER_ID);
        String username = request.getHeader(GatewayHeaders.USER_NAME);
        String authoritiesHeader = request.getHeader(GatewayHeaders.AUTHORITIES);
        String timestampHeader = request.getHeader(GatewayHeaders.TIMESTAMP);
        String signature = request.getHeader(GatewayHeaders.SIGNATURE);

        boolean identityPresent = StringUtils.hasText(userId) || StringUtils.hasText(username)
                || StringUtils.hasText(authoritiesHeader) || StringUtils.hasText(signature);

        if (!identityPresent) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!isTrusted(userId, username, authoritiesHeader, timestampHeader, signature)) {
            log.warn("Rejected request {} {}: identity headers are missing a valid gateway signature",
                    request.getMethod(), request.getRequestURI());
            SecurityContextHolder.clearContext();
            entryPoint.commence(request, response, new BadCredentialsException("Invalid gateway signature"));
            return;
        }

        List<SimpleGrantedAuthority> authorities = StringUtils.hasText(authoritiesHeader)
                ? Arrays.stream(authoritiesHeader.split(","))
                .map(String::trim)
                .filter(a -> !a.isEmpty())
                .map(SimpleGrantedAuthority::new)
                .toList()
                : List.of();

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userId, null, authorities);
        authentication.setDetails(username);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        filterChain.doFilter(request, response);
    }

    private boolean isTrusted(String userId, String username, String authorities, String timestampHeader, String signature) {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(timestampHeader) || !StringUtils.hasText(signature)) {
            return false;
        }

        long timestamp;
        try {
            timestamp = Long.parseLong(timestampHeader.trim());
        } catch (NumberFormatException e) {
            return false;
        }

        long drift = Math.abs(System.currentTimeMillis() - timestamp);
        if (drift > maxClockSkew.toMillis()) {
            return false;
        }

        String expected = GatewaySignature.sign(secret, userId, username, authorities, timestamp);
        return GatewaySignature.matches(expected, signature.trim());
    }
}
