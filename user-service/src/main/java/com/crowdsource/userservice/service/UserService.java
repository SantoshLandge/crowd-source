package com.crowdsource.userservice.service;

import com.crowdsource.userservice.dto.AuthResponse;
import com.crowdsource.userservice.dto.LoginRequest;
import com.crowdsource.userservice.dto.SignupRequest;
import com.crowdsource.userservice.dto.UserResponse;
import com.crowdsource.userservice.entity.RefreshToken;
import com.crowdsource.userservice.entity.Role;
import com.crowdsource.userservice.entity.User;
import com.crowdsource.userservice.entity.enums.UserStatus;
import com.crowdsource.userservice.exception.DuplicateEntityException;
import com.crowdsource.userservice.exception.InvalidRefreshTokenException;
import com.crowdsource.userservice.exception.ResourceNotFoundException;
import com.crowdsource.userservice.repository.RefreshTokenRepository;
import com.crowdsource.userservice.repository.RoleRepository;
import com.crowdsource.userservice.repository.UserRepository;
import com.crowdsource.userservice.security.CustomUserDetails;
import com.crowdsource.userservice.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepo;
    private final CustomUserDetailsService customUserDetailsService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public ResponseEntity<?> signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEntityException("Email already exists");
        }

        // Default: USER only
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new ResourceNotFoundException("Service configuration error, Default role 'USER' not found. Check database seeding."));

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .displayName(request.getDisplayName())
                .roles(Set.of(userRole))
                .status(UserStatus.ACTIVE)
                .build();

        user = userRepository.save(user);

        CustomUserDetails userDetails = new CustomUserDetails(user);

        String accessToken = jwtUtil.generateAccessToken(userDetails);
        String refreshTokenRaw = generateNewRefreshToken(userDetails.getUserId());

        // Build the user profile metadata payload
        AuthResponse userInfo = AuthResponse.builder()
                .email(userDetails.getUsername())
                .roles(userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .build();

        return jwtUtil.createAuthResponseWithCookies(accessToken, refreshTokenRaw, userInfo, "Signup successful");
    }

    public UserResponse getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // 1. Principal is now a String holding the userId from the Gateway header
        String userId = (String) auth.getPrincipal();

        // 2. Username/Email was passed into the details block, or we can use fallback string parameters
        String email = auth.getDetails() != null ? auth.getDetails().toString() : "";

        // 3. Extract roles directly out of the authenticated authorities collection
        List<String> roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return UserResponse.builder()
                .email(email)
                .roles(roles)
                .build();

    }

    public ResponseEntity<?> login(@Valid LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        String accessToken = jwtUtil.generateAccessToken(userDetails);

        String refreshTokenRaw = generateNewRefreshToken(userDetails.getUserId());

        // Build the user profile metadata payload
        AuthResponse userInfo = AuthResponse.builder()
                .email(userDetails.getUsername())
                .roles(userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .build();

        return jwtUtil.createAuthResponseWithCookies(accessToken, refreshTokenRaw, userInfo, "Login successful");
    }

    public ResponseEntity<?> refresh(HttpServletRequest request) {

        String refreshToken = extractRefreshToken(request);

        log.info("Refresh token request: {}", refreshToken);

        RefreshToken token = refreshTokenRepo.findByTokenHash(RefreshToken.hash(refreshToken))
                .filter(RefreshToken::isValid)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        CustomUserDetails userDetails = customUserDetailsService.loadUserByUserId(token.getUserId());
        String accessToken = jwtUtil.generateAccessToken(userDetails);

        // Rotate refresh token (security best practice)
        revokeToken(token);
        String refreshTokenRaw = generateNewRefreshToken(token.getUserId());

        // Build the user profile metadata payload
        AuthResponse userInfo = AuthResponse.builder()
                .email(userDetails.getUsername())
                .roles(userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .build();

        return jwtUtil.createAuthResponseWithCookies(accessToken, refreshTokenRaw, userInfo, "Token successful Refresh");
    }

    private void revokeToken(RefreshToken token) {
        token.setRevoked(true);
        refreshTokenRepo.save(token);
    }

    private String extractRefreshToken(HttpServletRequest request) {
        // Priority: cookie > header
        String token = request.getHeader("X-Refresh-Token");
        if (token == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("refresh_token".equals(cookie.getName())) {
                        token = cookie.getValue();
                    }
                }
            }
        }
        return token;
    }

    // Generate + persist new refresh token
    public String generateNewRefreshToken(Long userId) {
        // Generate secure opaque random string
        String rawToken = UUID.randomUUID() + "-" + System.currentTimeMillis() + "-" + ThreadLocalRandom.current().nextInt(1000, 9999);

        RefreshToken newToken = RefreshToken.create(rawToken, userId, Duration.ofDays(7));
        refreshTokenRepo.save(newToken);

        return rawToken;  // Return RAW to client
    }

    public ResponseEntity<?> logout(HttpServletRequest request) {

        // 1. Process database token revocation
        String refreshToken = extractRefreshToken(request);
        log.info("Logout request refresh token: {}", refreshToken);
        RefreshToken token = refreshTokenRepo.findByTokenHash(RefreshToken.hash(refreshToken))
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        token.setRevoked(true);
        refreshTokenRepo.save(token);

        // 2. Execute the complete structural server & browser wipe
        return purgeEntireSession("Logout successful. All sessions and cookies cleared.");

    }

    public ResponseEntity<?> logoutAllDevices(Authentication auth) {
        // 1. Process database token revocation
        Long userId = ((CustomUserDetails) auth.getPrincipal()).getUserId();
        refreshTokenRepo.deleteByUserId(userId);

        // 2. Execute the complete structural server & browser wipe
        return purgeEntireSession("Logout successful. All sessions and cookies cleared.");
    }

    // Dynamic Global Clean: Purges security context and instructs browser to wipe all storage
    public ResponseEntity<?> purgeEntireSession(String logoutMessage) {

        // 1. Clear Server-Side Security Thread Variables instantly
        SecurityContextHolder.clearContext();

        // 2. Instruct Browser to clear all Cookies, Storage, and Cache flags
        return ResponseEntity.ok()
                // "cookies" tells the browser to wipe every cookie for your domain
                // "storage" tells it to wipe localStorage / sessionStorage
                .header("Clear-Site-Data", "\"cookies\", \"storage\"")
                .body(Map.of("message", logoutMessage));
    }
}
