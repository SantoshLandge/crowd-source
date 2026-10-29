package com.crowdsource.eventservice.controller;

import com.crowdsource.eventservice.dto.CreateEvent;
import com.crowdsource.eventservice.dto.EventResponse;
import com.crowdsource.eventservice.service.EventService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

/**
 * Reached through the gateway as /api/v1/event/** (StripPrefix=1).
 * The {id}/capacity/** endpoints are internal: the gateway denies them for external callers and only
 * registration-service calls them (forwarding the caller's signed identity headers).
 */
@RestController
@RequestMapping("/v1/event")
@RequiredArgsConstructor
public class EventController {

    private static final String ORGANIZER_OR_ADMIN = "hasAnyRole('ORGANIZER','ADMIN')";

    private final EventService service;

    // ---- read ----------------------------------------------------------------

    @GetMapping
    public List<EventResponse> listLive() {
        return service.listLiveEvents();
    }

    @GetMapping("/mine")
    @PreAuthorize(ORGANIZER_OR_ADMIN)
    public List<EventResponse> mine() {
        return service.listMyEvents();
    }

    @GetMapping("/{id}")
    public EventResponse get(@PathVariable Long id) {
        return service.getEvent(id);
    }

    // ---- organizer / admin -----------------------------------------------------

    @PostMapping
    @PreAuthorize(ORGANIZER_OR_ADMIN)
    public ResponseEntity<EventResponse> create(@Valid @RequestBody CreateEvent request) {
        EventResponse created = service.createEvent(request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(created.id()).toUri();
        return ResponseEntity.created(location).body(created);
    }

    @PutMapping("/{id}")
    @PreAuthorize(ORGANIZER_OR_ADMIN)
    public EventResponse update(@PathVariable Long id, @Valid @RequestBody CreateEvent request) {
        return service.updateEvent(id, request);
    }

    @PostMapping("/{id}/submit")
    @PreAuthorize(ORGANIZER_OR_ADMIN)
    public EventResponse submit(@PathVariable Long id) {
        return service.submit(id);
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public EventResponse approve(@PathVariable Long id) {
        return service.approve(id);
    }

    @PostMapping("/{id}/cancel")
    @PreAuthorize(ORGANIZER_OR_ADMIN)
    public EventResponse cancel(@PathVariable Long id) {
        return service.cancel(id);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize(ORGANIZER_OR_ADMIN)
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }

    // ---- internal capacity API ---------------------------------------------------

    @GetMapping("/{id}/capacity")
    public ResponseEntity<Integer> capacity(@PathVariable Long id) {
        return ResponseEntity.ok(service.availableCapacity(id));
    }

    @PostMapping("/{id}/capacity/reserve")
    public ResponseEntity<Void> reserve(@PathVariable Long id, @RequestParam int quantity) {
        requirePositive(quantity);
        service.reserveCapacity(id, quantity);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/capacity/release")
    public ResponseEntity<Void> release(@PathVariable Long id, @RequestParam int quantity) {
        requirePositive(quantity);
        service.releaseCapacity(id, quantity);
        return ResponseEntity.ok().build();
    }

    private void requirePositive(int quantity) {
        if (quantity < 1) {
            throw new IllegalArgumentException("quantity must be >= 1");
        }
    }
}
