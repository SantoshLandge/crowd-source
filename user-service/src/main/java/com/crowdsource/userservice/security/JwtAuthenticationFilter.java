package com.crowdsource.userservice.security;

import com.crowdsource.userservice.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.info("Authorization Header Not Present");
                chain.doFilter(request, response);  // Skip to next
                return;
            }

            String jwt = authHeader.substring(7);

            if (!jwtUtil.validateToken(jwt)) {
                log.warn("Invalid or expired JWT token");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("""
                        {"error":"Invalid or expired JWT token", "status":401}
                        """);
                return;
            }

            Claims claims = jwtUtil.extractAllClaims(jwt);

            Long userId = claims.get("userId", Long.class);
            String email = claims.get("sub", String.class);
            @SuppressWarnings("unchecked")
            List<String> authoritiesList = claims.get("authorities", List.class);

            CustomUserDetails userDetails = new CustomUserDetails(userId, email, null, authoritiesList, true);

            if (SecurityContextHolder.getContext().getAuthentication() == null) {

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Authentication failed\"}");
            log.warn("JwtAuthenticationFilter JWT rejected: {}", e.getMessage());
        }

        chain.doFilter(request, response);
    }

}
