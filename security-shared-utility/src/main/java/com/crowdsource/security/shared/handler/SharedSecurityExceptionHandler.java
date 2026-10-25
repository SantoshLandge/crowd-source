package com.crowdsource.security.shared.handler;

import com.crowdsource.security.shared.dto.SecurityErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class SharedSecurityExceptionHandler implements AccessDeniedHandler, AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    // 1. Triggers when NOT logged in (HTTP 401)
    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException authEx) throws IOException {
        sendError(res, HttpStatus.UNAUTHORIZED, "Authentication failed: Missing or invalid Gateway credentials", req.getRequestURI(), Collections.emptyList());
    }

    // 2. Triggers when @PreAuthorize fails (HTTP 403)
    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res, AccessDeniedException accessDeniedEx) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        List<String> currentAuthorities = Collections.emptyList();

        if (auth != null) {
            currentAuthorities = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
        }

        log.warn("Shared Security Filter - Authorization failure for path: {} | Granted: {}", req.getRequestURI(), currentAuthorities);
        sendError(res, HttpStatus.FORBIDDEN, "Access Denied: You do not have the required role or permission authority.", req.getRequestURI(), currentAuthorities);
    }

    private <T> void sendError(HttpServletResponse res, HttpStatus httpStatus, String message, String path, List<String> authorities) throws IOException {
        res.setStatus(httpStatus.value());
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);

        SecurityErrorResponse errorPayload = new SecurityErrorResponse(
                Instant.now(),
                httpStatus.value(),
                httpStatus.getReasonPhrase(),
                message,
                path,
                authorities
        );

        res.getWriter().write(objectMapper.writeValueAsString(errorPayload));
    }
}
