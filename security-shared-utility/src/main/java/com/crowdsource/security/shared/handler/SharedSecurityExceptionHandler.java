package com.crowdsource.security.shared.handler;

import com.crowdsource.security.shared.dto.SecurityErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

/**
 * Produces consistent JSON bodies for 401 (not authenticated) and 403 (not authorized) responses.
 */
public class SharedSecurityExceptionHandler implements AccessDeniedHandler, AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(SharedSecurityExceptionHandler.class);

    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    // 401 - no (valid) identity
    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException authEx) throws IOException {
        sendError(res, HttpStatus.UNAUTHORIZED,
                "Authentication required: missing or invalid gateway credentials",
                req.getRequestURI(), Collections.emptyList());
    }

    // 403 - authenticated but not allowed (e.g. @PreAuthorize failed)
    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res, AccessDeniedException accessDeniedEx) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        List<String> currentAuthorities = auth == null
                ? Collections.emptyList()
                : auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

        log.warn("Authorization failure for {} {} | granted: {}", req.getMethod(), req.getRequestURI(), currentAuthorities);
        sendError(res, HttpStatus.FORBIDDEN,
                "Access denied: you do not have the required role or permission",
                req.getRequestURI(), currentAuthorities);
    }

    private void sendError(HttpServletResponse res, HttpStatus status, String message, String path,
                           List<String> authorities) throws IOException {
        res.setStatus(status.value());
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.setCharacterEncoding(StandardCharsets.UTF_8.name());
        res.setHeader("Cache-Control", "no-store");

        SecurityErrorResponse payload = new SecurityErrorResponse(
                Instant.now(), status.value(), status.getReasonPhrase(), message, path, authorities);
        res.getWriter().write(objectMapper.writeValueAsString(payload));
    }
}
