package com.crowdsource.eventservice.service;

import com.crowdsource.eventservice.dto.CreateEvent;
import com.crowdsource.eventservice.dto.EventResponse;
import com.crowdsource.eventservice.entity.Event;
import com.crowdsource.eventservice.entity.EventDetails;
import com.crowdsource.eventservice.entity.type.EventStatus;
import com.crowdsource.eventservice.entity.type.EventType;
import com.crowdsource.eventservice.exception.EventNotFoundException;
import com.crowdsource.eventservice.exception.InsufficientCapacityException;
import com.crowdsource.eventservice.exception.InvalidEventStateException;
import com.crowdsource.eventservice.repository.EventDetailsRepository;
import com.crowdsource.eventservice.repository.EventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Event lifecycle: DRAFT -> (organizer submits) PENDING -> (admin approves) LIVE; CANCELLED from any state.
 * Method-level role checks live on the controller; resource-level checks (ownership) live here.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EventService {

    private final EventRepository eventRepository;
    private final EventDetailsRepository eventDetailsRepository;

    // ------------------------------------------------------------------ queries

    @Transactional(readOnly = true)
    public List<EventResponse> listLiveEvents() {
        return eventRepository.findByStatusOrderByEventDateAsc(EventStatus.LIVE).stream().map(EventResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public List<EventResponse> listMyEvents() {
        List<Event> events = isAdmin() ? eventRepository.findAll()
                : eventRepository.findByOrganizerIdOrderByEventDateAsc(currentUserId());
        return events.stream().map(EventResponse::from).toList();
    }

    /** LIVE events are visible to everybody; other states only to the owner and admins (404 otherwise). */
    @Transactional(readOnly = true)
    public EventResponse getEvent(Long id) {
        Event event = find(id);
        if (event.getStatus() != EventStatus.LIVE && !canManage(event)) {
            throw new EventNotFoundException("Event " + id + " not found");
        }
        return EventResponse.from(event);
    }

    // ------------------------------------------------------------------ commands

    @Transactional
    public EventResponse createEvent(CreateEvent req) {
        Event event = Event.builder()
                .title(req.title().trim())
                .category(req.category())
                .eventDate(req.eventDate())
                .description(req.description())
                .eventType(req.eventType() != null ? req.eventType() : EventType.PHYSICAL)
                .venue(req.venue())
                .totalCapacity(req.totalCapacity())
                .availableCapacity(req.totalCapacity())
                .ticketPrice(req.ticketPrice())
                .status(EventStatus.DRAFT)
                .organizerId(currentUserId())
                .build();
        event = eventRepository.save(event);

        eventDetailsRepository.save(EventDetails.builder().eventId(event.getId()).build());
        log.info("Event {} created by user {}", event.getId(), event.getOrganizerId());
        return EventResponse.from(event);
    }

    @Transactional
    public EventResponse updateEvent(Long id, CreateEvent req) {
        Event event = findManageable(id);
        if (event.getStatus() != EventStatus.DRAFT) {
            throw new InvalidEventStateException("Only DRAFT events can be edited (current: " + event.getStatus() + ")");
        }
        event.setTitle(req.title().trim());
        event.setCategory(req.category());
        event.setEventDate(req.eventDate());
        event.setDescription(req.description());
        event.setEventType(req.eventType() != null ? req.eventType() : EventType.PHYSICAL);
        event.setVenue(req.venue());
        event.setTotalCapacity(req.totalCapacity());
        event.setAvailableCapacity(req.totalCapacity());   // DRAFT: nothing sold yet
        event.setTicketPrice(req.ticketPrice());
        return EventResponse.from(eventRepository.save(event));
    }

    @Transactional
    public EventResponse submit(Long id) {
        Event event = findManageable(id);
        requireStatus(event, EventStatus.DRAFT, "submitted");
        event.setStatus(EventStatus.PENDING);
        return EventResponse.from(eventRepository.save(event));
    }

    /** Admin only (enforced on the controller). */
    @Transactional
    public EventResponse approve(Long id) {
        Event event = find(id);
        requireStatus(event, EventStatus.PENDING, "approved");
        event.setStatus(EventStatus.LIVE);
        return EventResponse.from(eventRepository.save(event));
    }

    @Transactional
    public EventResponse cancel(Long id) {
        Event event = findManageable(id);
        if (event.getStatus() == EventStatus.CANCELLED) {
            throw new InvalidEventStateException("Event is already cancelled");
        }
        event.setStatus(EventStatus.CANCELLED);
        return EventResponse.from(eventRepository.save(event));
    }

    @Transactional
    public void delete(Long id) {
        Event event = findManageable(id);
        if (event.getStatus() != EventStatus.DRAFT) {
            throw new InvalidEventStateException("Only DRAFT events can be deleted; cancel the event instead");
        }
        eventDetailsRepository.deleteById(id);
        eventRepository.delete(event);
    }

    // ------------------------------------------------------------------ capacity (internal, called by registration-service)

    @Transactional(readOnly = true)
    public int availableCapacity(Long id) {
        return find(id).getAvailableCapacity();
    }

    /** Atomically reserves seats. */
    @Transactional
    public void reserveCapacity(Long id, int quantity) {
        find(id);   // 404 if unknown
        if (eventRepository.reduceCapacity(id, quantity) == 0) {
            throw new InsufficientCapacityException("Not enough capacity (or event is not open for registration)");
        }
        log.info("Reserved {} seats for event {}", quantity, id);
    }

    @Transactional
    public void releaseCapacity(Long id, int quantity) {
        find(id);
        if (eventRepository.increaseCapacity(id, quantity) == 0) {
            throw new InvalidEventStateException("Cannot release " + quantity + " seats: would exceed total capacity");
        }
        log.info("Released {} seats for event {}", quantity, id);
    }

    // ------------------------------------------------------------------ helpers

    private Event find(Long id) {
        return eventRepository.findById(id)
                .orElseThrow(() -> new EventNotFoundException("Event " + id + " not found"));
    }

    private Event findManageable(Long id) {
        Event event = find(id);
        if (!canManage(event)) {
            throw new AccessDeniedException("You do not own this event");
        }
        return event;
    }

    private boolean canManage(Event event) {
        return isAdmin() || event.getOrganizerId().equals(currentUserId());
    }

    private void requireStatus(Event event, EventStatus expected, String action) {
        if (event.getStatus() != expected) {
            throw new InvalidEventStateException("Event can only be " + action + " from status " + expected
                    + " (current: " + event.getStatus() + ")");
        }
    }

    private Authentication auth() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }
        return auth;
    }

    /** The principal is the user id (String) provided by the signed gateway headers. */
    private Long currentUserId() {
        try {
            return Long.valueOf(auth().getName());
        } catch (NumberFormatException e) {
            throw new AccessDeniedException("Invalid user identity");
        }
    }

    private boolean isAdmin() {
        return auth().getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }
}
