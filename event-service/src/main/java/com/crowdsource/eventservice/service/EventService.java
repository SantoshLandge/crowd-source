package com.crowdsource.eventservice.service;

import com.crowdsource.eventservice.dto.CreateEventRequest;
import com.crowdsource.eventservice.dto.EventResponse;
import com.crowdsource.eventservice.entity.Event;
import com.crowdsource.eventservice.entity.EventDetails;
import com.crowdsource.eventservice.entity.type.EventStatus;
import com.crowdsource.eventservice.repo.EventDetailsRepository;
import com.crowdsource.eventservice.repo.EventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class EventService {
    private final EventRepository eventRepository;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final EventDetailsRepository eventDetailsRepository;  // ADD THIS

    @Transactional
    public EventResponse createEvent(CreateEventRequest req) {
        Long organizerId = getCurrentOrganizerId();  // From JWT principal
        Event event = Event.builder()
                .title(req.getTitle())
                .description(req.getDescription())
                .type(req.getType())
                .venue(req.getVenue())
                .capacity(req.getCapacity())
                .startAt(req.getStartAt())
                .endAt(req.getEndAt())
                .organizerId(organizerId)
                .status(EventStatus.DRAFT)
                .build();
        event = eventRepository.save(event);

        // Save details
        EventDetails details = EventDetails.builder().eventId(event.getId()).build();
        eventDetailsRepository.save(details);

        // Kafka: Submit for approval
        kafkaTemplate.send("event-submitted", event.getId().toString(), Map.of(
                "eventId", event.getId(),
                "organizerId", organizerId,
                "title", event.getTitle()
        ));

        log.info("Event {} submitted by organizer {}", event.getId(), organizerId);
        return toResponse(event);
    }

    public List<EventResponse> searchEvents(EventStatus status, LocalDateTime date) {
        return eventRepository.searchLiveEvents(status, date).stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    public EventResponse getEvent(Long id) {
        return toResponse(eventRepository.findById(id).orElseThrow());
    }

    @Transactional
    public void updateEvent(Long id, CreateEventRequest req) {
        Long organizerId = getCurrentOrganizerId();
        Event event = eventRepository.findByIdAndOrganizerId(id, organizerId)
                .orElseThrow(() -> new RuntimeException("Not found or unauthorized"));
        // Update fields...
        eventRepository.save(event);
    }

    // Helpers
    private Long getCurrentOrganizerId() {
        // Extract from SecurityContext: ((UserDetailsImpl) principal).getUser().getId()
        return 1L; // TODO: Implement JWT principal extractor
    }

    private EventResponse toResponse(Event e) {
        return EventResponse.builder().id(e.getId()).status(e.getStatus()) /* etc */ .build();
    }
}
