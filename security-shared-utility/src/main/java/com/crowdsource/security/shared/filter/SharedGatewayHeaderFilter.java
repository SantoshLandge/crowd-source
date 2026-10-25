package com.crowdsource.security.shared.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class SharedGatewayHeaderFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Extract all three critical metrics from the Gateway headers
        String userId = request.getHeader("X-User-Id");
        String username = request.getHeader("X-User-Name");
        String authoritiesHeader = request.getHeader("X-User-Authorities");

        if (username != null && authoritiesHeader != null) {
            List<SimpleGrantedAuthority> authorities = Arrays.stream(authoritiesHeader.split(","))
                    .filter(auth -> !auth.trim().isEmpty())
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            // We use 'userId' as the primary principal ID, and 'username' as the details block
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);

            // Stores username as secondary metadata
            auth.setDetails(username);

            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }
/*
    // Option A: Direct Header Extraction (Easiest)
    @GetMapping("/my-events")
    public ResponseEntity<List<Event>> getMyEvents(@RequestHeader("X-User-Id") String userId) {
        return ResponseEntity.ok(eventService.findAllByUserId(userId));
    }

    // Option B: Spring Security Annotation (Cleanest)
    // Since we passed userId as the primary principal, @AuthenticationPrincipal maps it out directly:
    @GetMapping("/my-events")
    public ResponseEntity<List<Event>> getMyEvents(@AuthenticationPrincipal String userId) {
        return ResponseEntity.ok(eventService.findAllByUserId(userId));
    }

    // Option C: Imperative Code (For Service layers)
    // If you need to fetch the logged-in user's ID inside a deeply nested Service bean where HTTP headers aren't accessible:
    String currentUserId = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();*/

}
