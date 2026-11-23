package com.crowdsource.userservice.dto;

import java.util.UUID;
import com.crowdsource.userservice.entity.enums.UserStatus;
import java.time.LocalDateTime;
import java.util.Set;

public record UserResponseDto(
        UUID id,
        String email,
        String displayName,
        UserStatus status,
        Boolean emailVerified,
        LocalDateTime createdAt,
        Set<String> roles
) {}

