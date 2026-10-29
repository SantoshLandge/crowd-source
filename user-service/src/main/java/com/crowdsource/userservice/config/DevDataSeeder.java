package com.crowdsource.userservice.config;

import com.crowdsource.userservice.entity.Role;
import com.crowdsource.userservice.entity.User;
import com.crowdsource.userservice.entity.enums.UserStatus;
import com.crowdsource.userservice.repository.RoleRepository;
import com.crowdsource.userservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

/**
 * Creates demo accounts for local development only (disabled in the "prod" profile).
 * Passwords are hashed with the application's PasswordEncoder instead of being stored as {noop} in data.sql.
 */
@Slf4j
@Component
@Profile("!prod")
@RequiredArgsConstructor
public class DevDataSeeder implements ApplicationRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seed("user@crowdsource.com", "User", "user", "USER");
        seed("organizer@crowdsource.com", "Organizer", "organizer", "ORGANIZER");
        seed("admin@crowdsource.com", "Admin", "admin", "ADMIN");
        log.warn("DEV demo accounts available: user@crowdsource.com/user, organizer@crowdsource.com/organizer, "
                + "admin@crowdsource.com/admin - never run this profile in production");
    }

    private void seed(String email, String displayName, String rawPassword, String roleName) {
        if (userRepository.existsByEmail(email)) {
            return;
        }
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new IllegalStateException("Role " + roleName + " missing - check data.sql"));
        userRepository.save(User.builder()
                .email(email)
                .displayName(displayName)
                .password(passwordEncoder.encode(rawPassword))
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .roles(new HashSet<>(Set.of(role)))
                .build());
    }
}
