package com.crowdsource.registrationservice.dto;

import com.crowdsource.registrationservice.entity.Registration;
import com.crowdsource.registrationservice.entity.RegistrationStatus;

import java.math.BigDecimal;
import java.time.LocalDateTime;

public record RegistrationResponse(
        Long id,
        Long eventId,
        Integer quantity,
        BigDecimal totalAmount,
        RegistrationStatus status,
        Long paymentId,
        LocalDateTime createdAt
) {
    public static RegistrationResponse from(Registration r) {
        return new RegistrationResponse(r.getId(), r.getEventId(), r.getQuantity(), r.getTotalAmount(),
                r.getStatus(), r.getPaymentId(), r.getCreatedAt());
    }
}
