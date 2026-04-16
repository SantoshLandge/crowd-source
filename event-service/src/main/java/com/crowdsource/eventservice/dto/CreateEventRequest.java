package com.crowdsource.eventservice.dto;

import com.crowdsource.eventservice.entity.type.EventType;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class CreateEventRequest {
    @NotBlank
    private String title;
    private String description;
    private EventType type;
    private String venue;
    @Min(1) private Integer capacity;
    @Future
    private LocalDateTime startAt;
    private LocalDateTime endAt;
}
