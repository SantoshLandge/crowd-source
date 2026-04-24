package com.crowdsource.userservice.service;

import com.crowdsource.userservice.dto.AuthResponse;
import com.crowdsource.userservice.dto.SignupRequest;
import com.crowdsource.userservice.entity.RefreshToken;
import com.crowdsource.userservice.entity.Role;
import com.crowdsource.userservice.entity.User;
import com.crowdsource.userservice.entity.enums.UserStatus;
import com.crowdsource.userservice.exception.DuplicateEntityException;
import com.crowdsource.userservice.repository.RefreshTokenRepository;
import com.crowdsource.userservice.repository.RoleRepository;
import com.crowdsource.userservice.repository.UserRepository;
import com.crowdsource.userservice.security.CustomUserDetails;
import com.crowdsource.userservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepo;
    private final JwtUtil jwtUtil;

    public AuthResponse signup(SignupRequest request) throws DuplicateEntityException {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateEntityException("Email already exists");
        }

        // Default: USER only
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Default role: USER not found!"));

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .status(UserStatus.ACTIVE)
                .build();

        user = userRepository.save(user);

        CustomUserDetails userDetails = new CustomUserDetails(user);

        String accessToken = jwtUtil.generateAccessToken(userDetails);
        String refreshTokenRaw = generateNewRefreshToken(userDetails.getUserId());
        RefreshToken refreshToken = RefreshToken.create(refreshTokenRaw, userDetails.getUserId(), Duration.ofDays(7));
        refreshTokenRepo.save(refreshToken);

        return jwtUtil.buildAuthResponse(accessToken, refreshTokenRaw);
    }

    // Generate + persist new refresh token
    public String generateNewRefreshToken(Long userId) {
        // Generate secure opaque random string
        String rawToken = UUID.randomUUID() + "-" + System.currentTimeMillis() + "-" + ThreadLocalRandom.current().nextInt(1000, 9999);

        RefreshToken newToken = RefreshToken.create(rawToken, userId, Duration.ofDays(7));
        refreshTokenRepo.save(newToken);

        return rawToken;  // Return RAW to client
    }

}
