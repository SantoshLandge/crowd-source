package com.crowdsource.userservice.dto;

import com.crowdsource.userservice.entity.enums.UserStatus;
import java.time.LocalDateTime;
import java.util.Set;

public record UserResponseDto(
        Long id,
        String email,
        String displayName,
        UserStatus status,
        Boolean emailVerified,
        LocalDateTime createdAt,
        Set<String> roles
) {}

