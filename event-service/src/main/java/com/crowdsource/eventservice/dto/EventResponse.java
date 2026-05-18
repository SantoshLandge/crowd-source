package com.crowdsource.eventservice.dto;

import com.crowdsource.eventservice.entity.type.EventStatus;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EventResponse {
    private Long id;
    private String title;
    private EventStatus status;
}
