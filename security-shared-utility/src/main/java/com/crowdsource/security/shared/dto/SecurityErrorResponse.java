package com.crowdsource.security.shared.dto;

import java.time.Instant;
import java.util.List;

public record SecurityErrorResponse (
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        List<String> userAuthorities
) {}
