package com.crowdsource.userservice.service;

import com.crowdsource.userservice.dto.*;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepo;
    private final CustomUserDetailsService customUserDetailsService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    // ------------------------------------------------------------------ signup / login

    @Transactional
    public ResponseEntity<?> signup(SignupRequest request) {
        String email = normalize(request.getEmail());
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateEntityException("Email already exists");
        }

        // Self-service signup always yields the plain USER role (never trust a client supplied role)
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("Default role 'USER' not found. Check database seeding."));

        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(request.getPassword()))
                .displayName(request.getDisplayName().trim())
                .roles(new HashSet<>(Set.of(userRole)))
                .status(UserStatus.ACTIVE)
                .build();
        user = userRepository.save(user);

        return authResponse(new CustomUserDetails(user), "Signup successful", HttpStatus.CREATED);
    }

    @Transactional
    public ResponseEntity<?> login(LoginRequest request) {
        // Throws BadCredentialsException / DisabledException -> mapped to a generic 401 by GlobalExceptionHandler
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(normalize(request.getUsername()), request.getPassword()));

        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        userRepository.findById(userDetails.getId()).ifPresent(u -> u.setLastLoginAt(LocalDateTime.now()));

        return authResponse(userDetails, "Login successful", HttpStatus.OK);
    }

    // ------------------------------------------------------------------ refresh / logout

    /**
     * Rotates the refresh token. A refresh token can be used exactly once: presenting an already used (revoked)
     * token is treated as theft and revokes every session of that user.
     * noRollbackFor: the "revoke everything" side effect must be committed even though we then answer 401.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        String rawToken = extractRefreshToken(request);
        if (rawToken == null) {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }

        RefreshToken token = refreshTokenRepo.findByTokenHash(RefreshToken.hash(rawToken))
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (token.isRevoked()) {
            log.warn("Refresh token reuse detected for user {} - revoking all sessions", token.getUserId());
            refreshTokenRepo.revokeAllByUserId(token.getUserId());
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }
        if (token.isExpired()) {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }

        // Atomic single-use: if two requests race with the same token only one gets 1 here
        if (refreshTokenRepo.revokeIfActive(token.getId()) == 0) {
            log.warn("Concurrent refresh with the same token for user {} - revoking all sessions", token.getUserId());
            refreshTokenRepo.revokeAllByUserId(token.getUserId());
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }

        CustomUserDetails userDetails = customUserDetailsService.loadUserByUserId(token.getUserId());
        if (!userDetails.isEnabled()) {
            refreshTokenRepo.revokeAllByUserId(token.getUserId());
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }

        return authResponse(userDetails, "Token refreshed", HttpStatus.OK);
    }

    /** Idempotent: always clears the cookies, revokes the presented refresh token if it exists. */
    @Transactional
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String rawToken = extractRefreshToken(request);
        if (rawToken != null) {
            refreshTokenRepo.findByTokenHash(RefreshToken.hash(rawToken))
                    .ifPresent(t -> refreshTokenRepo.revokeIfActive(t.getId()));
        }
        return jwtUtil.createLogoutResponse("Logout successful");
    }

    @Transactional
    public ResponseEntity<?> logoutAllDevices(Long userId) {
        int revoked = refreshTokenRepo.revokeAllByUserId(userId);
        log.info("Logout from all devices for user {} ({} sessions revoked)", userId, revoked);
        return jwtUtil.createLogoutResponse("Logged out from all devices");
    }

    // ------------------------------------------------------------------ profile / admin

    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(Long userId) {
        User user = findUser(userId);
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .displayName(user.getDisplayName())
                .roles(user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .build();
    }

    @Transactional
    public UserResponse updateProfile(Long userId, UpdateProfileRequest request) {
        User user = findUser(userId);
        user.setDisplayName(request.getDisplayName().trim());
        return getCurrentUser(userRepository.save(user).getId());
    }

    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(user -> new UserResponseDto(
                        user.getId(),
                        user.getEmail(),
                        user.getDisplayName(),
                        user.getStatus(),
                        user.getEmailVerified(),
                        user.getCreatedAt(),
                        user.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet())))
                .toList();
    }

    /** Admin: activate / suspend an account. Anything other than ACTIVE kills all existing sessions. */
    @Transactional
    public UserResponseDto updateUserStatus(Long actingAdminId, Long targetUserId, UserStatus status) {
        if (actingAdminId.equals(targetUserId)) {
            throw new IllegalStateException("You cannot change the status of your own account");
        }
        User user = findUser(targetUserId);
        user.setStatus(status);
        user = userRepository.save(user);
        if (status != UserStatus.ACTIVE) {
            refreshTokenRepo.revokeAllByUserId(user.getId());
        }
        return new UserResponseDto(user.getId(), user.getEmail(), user.getDisplayName(), user.getStatus(),
                user.getEmailVerified(), user.getCreatedAt(),
                user.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet()));
    }

    // ------------------------------------------------------------------ helpers

    private ResponseEntity<?> authResponse(CustomUserDetails userDetails, String message, HttpStatus status) {
        String accessToken = jwtUtil.generateAccessToken(userDetails);
        String refreshTokenRaw = generateNewRefreshToken(userDetails.getId());

        AuthResponse userInfo = AuthResponse.builder()
                .email(userDetails.getUsername())
                .roles(userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .build();

        return jwtUtil.createAuthResponseWithCookies(status, accessToken, refreshTokenRaw, userInfo, message);
    }

    /** Generates + persists a new refresh token; returns the RAW value (only its hash is stored). */
    public String generateNewRefreshToken(Long userId) {
        byte[] random = new byte[48];
        SECURE_RANDOM.nextBytes(random);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(random);

        refreshTokenRepo.save(RefreshToken.create(rawToken, userId, JwtUtil.REFRESH_TOKEN_TTL));
        return rawToken;
    }

    private String extractRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (JwtUtil.REFRESH_COOKIE.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                    return cookie.getValue();
                }
            }
        }
        String header = request.getHeader("X-Refresh-Token");   // non-browser clients
        return header != null && !header.isBlank() ? header : null;
    }

    private User findUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    private String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
