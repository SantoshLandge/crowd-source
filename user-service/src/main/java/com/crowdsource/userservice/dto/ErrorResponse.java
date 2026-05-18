package com.crowdsource.userservice.dto;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
@Builder
public class ErrorResponse {
    private final int status;
    private final String error;
    private final String message;
    private final Map<String, String> validationErrors;  // Field-specific errors
    private final LocalDateTime timestamp;
    private final String path;
}
