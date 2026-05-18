package com.crowdsource.eventservice.controller;

import com.crowdsource.eventservice.entity.Event;
import com.crowdsource.eventservice.repository.EventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/v1/event")
@RequiredArgsConstructor
public class EventController {

    private final EventRepository eventRepository;

    @GetMapping
    public List<Event> getAllEvents() {
        return eventRepository.findAll();
    }

    @PostMapping
    public Event createEvent(@RequestBody Event event) {
        event.setAvailableCapacity(event.getTotalCapacity());
        event.setStatus("DRAFT");
        return eventRepository.save(event);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Event> getEvent(@PathVariable Long id) {
        return eventRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/publish")
    public ResponseEntity<?> publishEvent(@PathVariable Long id) {
        Event event = eventRepository.findById(id).orElseThrow();
        event.setStatus("PUBLISHED");
        eventRepository.save(event);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/{id}/capacity")
    public ResponseEntity<Integer> checkCapacity(@PathVariable Long id) {
        Event event = eventRepository.findById(id).orElseThrow();
        return ResponseEntity.ok(event.getAvailableCapacity());
    }

    // HOLD capacity (temporary hold before payment)
    @PostMapping("/{id}/capacity/hold")
    public ResponseEntity<Void> holdCapacity(@PathVariable Long id, @RequestParam int quantity) {
        Event event = eventRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Event not found"));

        // Check if enough capacity
        if (event.getAvailableCapacity() < quantity) {
            throw new RuntimeException("Not enough capacity");
        }

        // For Sprint 1, we'll just validate
        // In real implementation, you'd store the hold in Redis/DB
        System.out.println("Holding " + quantity + " tickets for event: " + id);

        return ResponseEntity.ok().build();
    }

    // CONFIRM capacity (after successful payment)
    @PostMapping("/{id}/capacity/confirm")
    public ResponseEntity<Void> confirmCapacity(@PathVariable Long id, @RequestParam int quantity) {
        int updated = eventRepository.reduceCapacity(id, quantity);

        if (updated == 0) {
            throw new RuntimeException("Failed to confirm capacity. Event might not have enough capacity.");
        }

        log.info("Confirmed {} tickets for event: {}", quantity, id);
        return ResponseEntity.ok().build();
    }

    // RELEASE capacity (after cancellation)
    @PostMapping("/{id}/capacity/release")
    public ResponseEntity<Void> releaseCapacity(@PathVariable Long id, @RequestParam int quantity) {
        eventRepository.increaseCapacity(id, quantity);
        log.info("Released {} tickets for event: {}", quantity, id);
        return ResponseEntity.ok().build();
    }
}
