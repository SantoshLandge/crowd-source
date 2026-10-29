package com.crowdsource.registrationservice.service;

import com.crowdsource.registrationservice.client.EventClient;
import com.crowdsource.registrationservice.client.PaymentClient;
import com.crowdsource.registrationservice.dto.EventView;
import com.crowdsource.registrationservice.dto.PaymentResult;
import com.crowdsource.registrationservice.dto.RegistrationRequest;
import com.crowdsource.registrationservice.dto.RegistrationResponse;
import com.crowdsource.registrationservice.entity.Registration;
import com.crowdsource.registrationservice.entity.RegistrationStatus;
import com.crowdsource.registrationservice.exception.RegistrationConflictException;
import com.crowdsource.registrationservice.exception.RegistrationNotFoundException;
import com.crowdsource.registrationservice.repository.RegistrationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;

/**
 * Registration saga: verify event -> reserve seats (atomic) -> charge -> CONFIRMED.
 * Any failure after the reservation releases the seats again and marks the registration FAILED.
 * Deliberately not @Transactional: remote calls must not run inside a DB transaction, and each state change
 * has to be committed immediately so a failed attempt is still recorded.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {

    private final RegistrationRepository repository;
    private final EventClient eventClient;
    private final PaymentClient paymentClient;

    public RegistrationResponse register(RegistrationRequest request) {
        Long userId = currentUserId();
        int quantity = request.quantity();

        EventView event = eventClient.getEvent(request.eventId());   // price comes from the server, never from the client
        if (!"LIVE".equals(event.status())) {
            throw new RegistrationConflictException("Event is not open for registration");
        }
        BigDecimal total = BigDecimal.valueOf(event.ticketPrice()).multiply(BigDecimal.valueOf(quantity));

        Registration registration = repository.save(Registration.builder()
                .userId(userId)
                .eventId(event.id())
                .quantity(quantity)
                .totalAmount(total)
                .status(RegistrationStatus.PENDING)
                .build());

        try {
            eventClient.reserve(event.id(), quantity);
        } catch (RuntimeException e) {
            markFailed(registration);
            throw e;
        }

        if (total.signum() > 0) {
            PaymentResult payment;
            try {
                payment = paymentClient.process(String.valueOf(registration.getId()), total);
            } catch (RuntimeException e) {
                // Payment is idempotent per registration id, so an ambiguous failure can be reconciled/retried
                compensate(registration);
                throw e;
            }
            if (payment == null || !"SUCCESS".equals(payment.status())) {
                compensate(registration);
                throw new RegistrationConflictException("Payment was declined");
            }
            registration.setPaymentId(payment.paymentId());
        }

        registration.setStatus(RegistrationStatus.CONFIRMED);
        log.info("Registration {} confirmed for user {} (event {}, qty {})",
                registration.getId(), userId, event.id(), quantity);
        return RegistrationResponse.from(repository.save(registration));
    }

    public List<RegistrationResponse> myRegistrations() {
        return repository.findByUserIdOrderByCreatedAtDesc(currentUserId()).stream()
                .map(RegistrationResponse::from).toList();
    }

    public RegistrationResponse get(Long id) {
        return RegistrationResponse.from(findAccessible(id));
    }

    public RegistrationResponse cancel(Long id) {
        Registration registration = findAccessible(id);
        if (registration.getStatus() != RegistrationStatus.CONFIRMED) {
            throw new RegistrationConflictException("Only CONFIRMED registrations can be cancelled");
        }
        if (registration.getPaymentId() != null) {
            paymentClient.refund(registration.getPaymentId());   // if this fails nothing has changed yet
        }
        eventClient.release(registration.getEventId(), registration.getQuantity());
        registration.setStatus(RegistrationStatus.CANCELLED);
        return RegistrationResponse.from(repository.save(registration));
    }

    // ---------------------------------------------------------------- helpers

    private void compensate(Registration registration) {
        try {
            eventClient.release(registration.getEventId(), registration.getQuantity());
        } catch (RuntimeException e) {
            log.error("MANUAL ACTION NEEDED: could not release {} seats of event {} for registration {}",
                    registration.getQuantity(), registration.getEventId(), registration.getId(), e);
        }
        markFailed(registration);
    }

    private void markFailed(Registration registration) {
        registration.setStatus(RegistrationStatus.FAILED);
        repository.save(registration);
    }

    /** Owner or admin; everybody else gets a 404 so ids cannot be probed. */
    private Registration findAccessible(Long id) {
        Registration registration = repository.findById(id)
                .orElseThrow(() -> new RegistrationNotFoundException("Registration " + id + " not found"));
        if (!registration.getUserId().equals(currentUserId()) && !isAdmin()) {
            throw new RegistrationNotFoundException("Registration " + id + " not found");
        }
        return registration;
    }

    private Authentication auth() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }
        return auth;
    }

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
