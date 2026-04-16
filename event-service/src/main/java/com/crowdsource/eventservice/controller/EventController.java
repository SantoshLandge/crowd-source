package com.crowdsource.eventservice.controller;

import com.crowdsource.eventservice.dto.CreateEventRequest;
import com.crowdsource.eventservice.dto.EventResponse;
import com.crowdsource.eventservice.entity.type.EventStatus;
import com.crowdsource.eventservice.service.EventService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/v1/events")
@RequiredArgsConstructor
public class EventController {
    private final EventService eventService;

    @GetMapping("/search")
    public List<EventResponse> search(
            @RequestParam(defaultValue = "LIVE") String status,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime date) {
        return eventService.searchEvents(EventStatus.valueOf(status), date);
    }

    @GetMapping("/{id}")
    public EventResponse getEvent(@PathVariable Long id) {
        return eventService.getEvent(id);
    }

    @PostMapping
//    @PreAuthorize("hasRole('ORGANIZER')")
    public ResponseEntity<String> submitEvent(@Valid @RequestBody CreateEventRequest req) {
        eventService.createEvent(req);
        return ResponseEntity.accepted().body("Event submitted for approval");
    }

    @PutMapping("/{id}")
//    @PreAuthorize("hasRole('ORGANIZER')")
    public ResponseEntity<Void> updateEvent(@PathVariable Long id, @Valid @RequestBody CreateEventRequest req) {
        eventService.updateEvent(id, req);
        return ResponseEntity.noContent().build();
    }
}
