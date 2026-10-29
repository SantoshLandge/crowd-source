package com.crowdsource.registrationservice.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PaymentResult(Long paymentId, String transactionId, String status) {
}
