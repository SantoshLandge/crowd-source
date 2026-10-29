package com.crowdsource.registrationservice.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public record RegistrationRequest(
        @NotNull Long eventId,
        @NotNull @Min(1) @Max(10) Integer quantity
) {
}
