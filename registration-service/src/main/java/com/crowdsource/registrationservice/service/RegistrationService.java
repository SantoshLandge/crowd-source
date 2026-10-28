package com.crowdsource.registrationservice.service;

import com.crowdsource.registrationservice.client.EventClient;
import com.crowdsource.registrationservice.client.PaymentClient;
import com.crowdsource.registrationservice.dto.RegistrationRequest;
import com.crowdsource.registrationservice.entity.Registration;
import com.crowdsource.registrationservice.repository.RegistrationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegistrationService {

    private final RegistrationRepository registrationRepository;
    private final EventClient eventClient;
    private final PaymentClient paymentClient;

    @Transactional
    public Registration register(RegistrationRequest request) {
        log.info("Processing registration for event: {}", request.getEventId());

        // 1. Check event capacity
        Integer availableCapacity = eventClient.checkCapacity(request.getEventId());
        if (availableCapacity < request.getTicketQuantity()) {
            throw new RuntimeException("No capacity available. Available: " + availableCapacity);
        }

        // 2. Hold capacity temporarily
        eventClient.holdCapacity(request.getEventId(), request.getTicketQuantity());

        // 3. Create registration
        Registration registration = new Registration();
        registration.setEventId(request.getEventId());
        registration.setAttendeeName(request.getAttendeeName());
        registration.setAttendeeEmail(request.getAttendeeEmail());
        registration.setTicketQuantity(request.getTicketQuantity());
        registration.setTotalAmount(BigDecimal.valueOf(request.getTicketQuantity() * 100));
        registration.setStatus("PENDING");
        registration.setRegistrationDate(LocalDateTime.now());

        registration = registrationRepository.save(registration);
        log.info("Registration created with ID: {}", registration.getId());

        // 4. Process payment
        try {
            String paymentId = paymentClient.processPayment(
                    registration.getId().toString(),
                    registration.getTotalAmount()
            );

            registration.setPaymentId(paymentId);
            registration.setStatus("CONFIRMED");

            // 5. Confirm capacity (permanent reduction)
            eventClient.confirmCapacity(request.getEventId(), request.getTicketQuantity());

            registrationRepository.save(registration);
            log.info("Registration confirmed: {}", registration.getId());

            return registration;

        } catch (Exception e) {
            log.error("Payment failed: {}", e.getMessage());
            registration.setStatus("FAILED");
            registrationRepository.save(registration);

            // Release the held capacity
            eventClient.releaseCapacity(request.getEventId(), request.getTicketQuantity());

            throw new RuntimeException("Payment processing failed: " + e.getMessage());
        }
    }

    @Transactional
    public void cancelRegistration(Long registrationId) {
        Registration registration = registrationRepository.findById(registrationId)
                .orElseThrow(() -> new RuntimeException("Registration not found"));

        if (!"CONFIRMED".equals(registration.getStatus())) {
            throw new RuntimeException("Only confirmed registrations can be cancelled");
        }

        // Process refund
        paymentClient.processRefund(registration.getPaymentId());

        // Release capacity back to event
        eventClient.releaseCapacity(registration.getEventId(), registration.getTicketQuantity());

        registration.setStatus("CANCELLED");
        registrationRepository.save(registration);

        log.info("Registration cancelled: {}", registrationId);
    }
}
