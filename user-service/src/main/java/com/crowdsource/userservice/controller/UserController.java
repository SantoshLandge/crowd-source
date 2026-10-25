package com.crowdsource.userservice.controller;

import com.crowdsource.userservice.dto.LoginRequest;
import com.crowdsource.userservice.dto.SignupRequest;
import com.crowdsource.userservice.dto.UserResponse;
import com.crowdsource.userservice.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest request) {
        log.debug("Signup attempt for: {}", request.getEmail());
        return userService.signup(request);
    }

    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getCurrentUser() {
        log.debug("User profile request");
        return ResponseEntity.ok(userService.getCurrentUser());
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        log.debug("Login attempt for: {}", request.getUsername());
        return userService.login(request);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        return userService.refresh(request);
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAllDevices(Authentication auth) {
        log.debug("Logout all devices");
        userService.logoutAllDevices(auth);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        userService.logout(request);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/debug")
    public String debug() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getAuthorities().toString();
    }

    @PutMapping({"", "/{id}"})
    @PreAuthorize("hasAuthority('update:user') and (hasRole('ADMIN') or #id?.toString() == authentication.principal)")
    public ResponseEntity<String> updateUser(
            @PathVariable(required = false) Long id,
            @AuthenticationPrincipal String loggedInUserId) {

        // Fallback inside the method logic
        Long targetUserId = (id != null) ? id : Long.valueOf(loggedInUserId);

        return ResponseEntity.ok("Profile updated successfully for ID: " + targetUserId);
    }

}
