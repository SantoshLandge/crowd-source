package com.crowdsource.registrationservice.dto;

import java.util.UUID;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PaymentResult(UUID paymentId, String transactionId, String status) {
}
