package com.crowdsource.eventservice.dto;

import com.crowdsource.eventservice.entity.Event;
import com.crowdsource.eventservice.entity.type.EventStatus;
import com.crowdsource.eventservice.entity.type.EventType;

import java.time.LocalDateTime;

public record EventResponse(
        Long id,
        String title,
        String category,
        LocalDateTime eventDate,
        String description,
        EventType eventType,
        String venue,
        Integer totalCapacity,
        Integer availableCapacity,
        Integer ticketPrice,
        EventStatus status,
        Long organizerId
) {
    public static EventResponse from(Event e) {
        return new EventResponse(e.getId(), e.getTitle(), e.getCategory(), e.getEventDate(), e.getDescription(),
                e.getEventType(), e.getVenue(), e.getTotalCapacity(), e.getAvailableCapacity(), e.getTicketPrice(),
                e.getStatus(), e.getOrganizerId());
    }
}
