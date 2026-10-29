package com.crowdsource.userservice.controller;

import com.crowdsource.userservice.dto.UpdateUserStatusRequest;
import com.crowdsource.userservice.dto.UserResponseDto;
import com.crowdsource.userservice.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Admin endpoints. Guarded twice: the gateway only lets ROLE_ADMIN reach /api/auth/admin/**, and the
 * 'manage:users' authority is checked here. (Previously these used read:user / update:user, which every
 * normal USER also has - any user could list all accounts.)
 */
@RestController
@RequestMapping("/auth/admin/v1")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('manage:users')")
public class AdminController {

    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<UserResponseDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @PatchMapping("/users/{id}/status")
    public ResponseEntity<UserResponseDto> updateUserStatus(@PathVariable Long id,
                                                            @Valid @RequestBody UpdateUserStatusRequest request,
                                                            Authentication authentication) {
        Long adminId = Long.valueOf(authentication.getName());
        return ResponseEntity.ok(userService.updateUserStatus(adminId, id, request.getStatus()));
    }
}
