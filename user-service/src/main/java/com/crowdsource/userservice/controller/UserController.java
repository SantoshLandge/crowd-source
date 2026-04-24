package com.crowdsource.userservice.controller;

import com.crowdsource.userservice.dto.AuthResponse;
import com.crowdsource.userservice.dto.LoginRequest;
import com.crowdsource.userservice.dto.SignupRequest;
import com.crowdsource.userservice.dto.UserResponse;
import com.crowdsource.userservice.entity.RefreshToken;
import com.crowdsource.userservice.exception.DuplicateEntityException;
import com.crowdsource.userservice.exception.InvalidRefreshTokenException;
import com.crowdsource.userservice.repository.RefreshTokenRepository;
import com.crowdsource.userservice.security.CustomUserDetails;
import com.crowdsource.userservice.service.CustomUserDetailsService;
import com.crowdsource.userservice.service.UserService;
import com.crowdsource.userservice.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepo;
    private final CustomUserDetailsService customUserDetailsService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) throws DuplicateEntityException {
        log.info("Signup attempt for: {}", request.getUsername());
        return ResponseEntity.ok(userService.signup(request));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();

        return ResponseEntity.ok(UserResponse.builder()
                .username(userDetails.getUsername())
                .email(userDetails.getUsername())
                .roles(jwtUtil.extractRoles(userDetails.getAuthorities()))
                .build());
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login attempt for: {}", request.getUsername());
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        String accessToken = jwtUtil.generateAccessToken(userDetails);

        String refreshTokenRaw = generateNewRefreshToken(userDetails.getUserId());

        AuthResponse response = jwtUtil.buildAuthResponse(accessToken, refreshTokenRaw);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(HttpServletRequest request) throws InvalidRefreshTokenException {
        String refreshToken = extractRefreshToken(request);
        log.info("Refresh token request: {}", refreshToken);

        RefreshToken token = refreshTokenRepo.findByTokenHash(RefreshToken.hash(refreshToken))
                .filter(RefreshToken::isValid)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        CustomUserDetails userDetails = customUserDetailsService.loadUserByUserId(token.getUserId());
        String newAccessToken = jwtUtil.generateAccessToken(userDetails);

        // Rotate refresh token (security best practice)
        revokeToken(token);
        String refreshTokenRaw = generateNewRefreshToken(token.getUserId());

        return ResponseEntity.ok(jwtUtil.buildAuthResponse(newAccessToken, refreshTokenRaw));
    }

    private void revokeToken(RefreshToken token) {
        token.setRevoked(true);
        refreshTokenRepo.save(token);
    }

    // Generate + persist new Opaque random string refresh token (NOT JWT)
    public String generateNewRefreshToken(Long userId) {
        String rawToken = UUID.randomUUID() + "-" +
                System.currentTimeMillis() + "-" +
                ThreadLocalRandom.current().nextInt(1000, 9999);

        RefreshToken newToken = RefreshToken.create(rawToken, userId, Duration.ofDays(7));
        refreshTokenRepo.save(newToken);

        return rawToken;
    }

    private String extractRefreshToken(HttpServletRequest request) {
        // Priority: cookie > header
        String token = request.getHeader("X-Refresh-Token");
        if (token == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("refreshToken".equals(cookie.getName())) {
                        token = cookie.getValue();
                    }
                }
            }
        }
        return token;
    }

    @PostMapping("/logout-all")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> logoutAllDevices(Authentication auth) {
        Long userId = ((CustomUserDetails) auth.getPrincipal()).getUserId();
        refreshTokenRepo.deleteByUserId(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) throws InvalidRefreshTokenException {
        String refreshToken = extractRefreshToken(request);
        log.info("Logout request refresh token: {}", refreshToken);
        RefreshToken token = refreshTokenRepo.findByTokenHash(RefreshToken.hash(refreshToken))
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        token.setRevoked(true);
        refreshTokenRepo.save(token);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/debug")
    public String debug() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getAuthorities().toString();
    }

}
