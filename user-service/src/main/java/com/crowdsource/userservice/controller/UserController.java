package com.crowdsource.userservice.controller;

import com.crowdsource.userservice.dto.LoginRequest;
import com.crowdsource.userservice.dto.SignupRequest;
import com.crowdsource.userservice.dto.UpdateProfileRequest;
import com.crowdsource.userservice.dto.UserResponse;
import com.crowdsource.userservice.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Public (no token needed, whitelisted in the gateway and in security.shared.public-paths):
 * signup, login, refresh, logout. Everything else requires authentication.
 */
@Slf4j
@RestController
@RequestMapping("/auth/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest request) {
        log.debug("Signup attempt");
        return userService.signup(request);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        log.debug("Login attempt");
        return userService.login(request);
    }

    // Called when the access token has (almost) expired, so it must NOT require an authenticated caller:
    // the refresh_token cookie is the credential. (@PreAuthorize("isAuthenticated()") made this endpoint unusable.)
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request) {
        return userService.refresh(request);
    }

    // Public + idempotent: works with only the refresh cookie and always clears the cookies.
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        return userService.logout(request);
    }

    @PostMapping("/logout-all")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> logoutAllDevices(Authentication authentication) {
        return userService.logoutAllDevices(currentUserId(authentication));
    }

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        return ResponseEntity.ok(userService.getCurrentUser(currentUserId(authentication)));
    }

    @PutMapping("/update")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserResponse> updateMyProfile(Authentication authentication,
                                                        @Valid @RequestBody UpdateProfileRequest request) {
        return ResponseEntity.ok(userService.updateProfile(currentUserId(authentication), request));
    }

    /** The principal is the user id (String) set by the gateway header filter. */
    private Long currentUserId(Authentication authentication) {
        return Long.valueOf(authentication.getName());
    }
}
