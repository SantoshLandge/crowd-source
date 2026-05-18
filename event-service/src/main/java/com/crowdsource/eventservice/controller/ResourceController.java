package com.crowdsource.eventservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/event/resources")
public class ResourceController {

    @GetMapping("/me")
    public String debugTokenClaims(Authentication authentication) {
        // authentication.getPrincipal() returns a Jwt object in OAuth2 Resource Servers
        if (authentication.getPrincipal() instanceof Jwt jwt) {

            // 1. Get userId (Custom claim we added)
            // Note: If you stored it as a Long in JwtUtil, getClaim might return Long or Integer
            Long userId = jwt.getClaim("userId");

            // 2. Get username (The standard 'sub' claim or our custom 'username' claim)
            String username = jwt.getClaim("username");

            // Print to console
            System.out.println("-----------------------------------");
            System.out.println("LOGGED IN USER INFO:");
            System.out.println("User ID: " + userId);
            System.out.println("Username: " + username);
            System.out.println("-----------------------------------");

            return "Logged in as: " + username + " (ID: " + userId + ")";
        }

        return "Principal is not an instance of Jwt. Check your SecurityConfig!";
    }

    // Anyone with a valid USER role can view
    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public String read() {
        return "Read Access Granted";
    }

    // Only users with ADMIN role can delete
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String delete(@PathVariable Long id) {
        return "Resource " + id + " deleted";
    }

    // Check for specific logic (e.g., matching User ID from token)
    @PutMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.token.claims['userId']")
    public String update(@PathVariable Long userId) {
        return "User " + userId + " updated";
    }
}
