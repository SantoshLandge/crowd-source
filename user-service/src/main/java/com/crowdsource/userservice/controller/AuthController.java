package com.crowdsource.userservice.controller;

import com.crowdsource.userservice.dto.AuthResponse;
import com.crowdsource.userservice.dto.LoginRequest;
import com.crowdsource.userservice.dto.SignupRequest;
import com.crowdsource.userservice.dto.UserResponse;
import com.crowdsource.userservice.security.CustomUserDetails;
import com.crowdsource.userservice.service.CustomUserDetailsService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final CustomUserDetailsService authService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {
        log.info("Signup attempt for: {}", request.getUsername());
        return ResponseEntity.ok(authService.signup(request));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();

        return ResponseEntity.ok(UserResponse.builder()
                .id(userDetails.user().getId())
                .username(userDetails.getUsername())
                .email(userDetails.user().getEmail())
                .role(userDetails.user().getRole())
                .build());
    }
}

