package com.crowdsource.eventservice.dto;

import com.crowdsource.eventservice.entity.type.EventType;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.time.LocalDateTime;

/** Used for create and (full) update. Status is never accepted from the client. */
public record CreateEvent(
        @NotBlank @Size(max = 150) String title,
        @Size(max = 100) String category,
        @NotNull @Future LocalDateTime eventDate,
        @Size(max = 2000) String description,
        EventType eventType,
        @Size(max = 255) String venue,
        @NotNull @Min(1) Integer totalCapacity,
        @NotNull @PositiveOrZero Integer ticketPrice
) {
}
