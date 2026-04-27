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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

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

    public AuthResponse signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEntityException("Email already exists");
        }

        // Default: USER only
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new ResourceNotFoundException("Service configuration error, Default role 'USER' not found. Check database seeding."));

        User user = User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .status(UserStatus.ACTIVE)
                .build();

        user = userRepository.save(user);

        CustomUserDetails userDetails = new CustomUserDetails(user);

        String accessToken = jwtUtil.generateAccessToken(userDetails);
        String refreshTokenRaw = generateNewRefreshToken(userDetails.getUserId());

        return jwtUtil.buildAuthResponse(accessToken, refreshTokenRaw);
    }

    public UserResponse getCurrentUser() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();

        return UserResponse.builder()
                .username(userDetails.getUsername())
                .email(userDetails.getUsername())
                .roles(jwtUtil.extractRoles(userDetails.getAuthorities()))
                .build();

    }

    public AuthResponse login(@Valid LoginRequest request) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
        String accessToken = jwtUtil.generateAccessToken(userDetails);

        String refreshTokenRaw = generateNewRefreshToken(userDetails.getUserId());

        return jwtUtil.buildAuthResponse(accessToken, refreshTokenRaw);
    }

    public AuthResponse refresh(HttpServletRequest request) {

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

        return jwtUtil.buildAuthResponse(newAccessToken, refreshTokenRaw);
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
                    if ("refreshToken".equals(cookie.getName())) {
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

    public void logout(HttpServletRequest request) {
        String refreshToken = extractRefreshToken(request);
        log.info("Logout request refresh token: {}", refreshToken);
        RefreshToken token = refreshTokenRepo.findByTokenHash(RefreshToken.hash(refreshToken))
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        token.setRevoked(true);
        refreshTokenRepo.save(token);
    }

    public void logoutAllDevices(Authentication auth) {
        Long userId = ((CustomUserDetails) auth.getPrincipal()).getUserId();
        refreshTokenRepo.deleteByUserId(userId);
    }
}
