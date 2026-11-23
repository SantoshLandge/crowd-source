package com.crowdsource.paymentservice.dto;

import java.util.UUID;
public record PaymentResponse(UUID paymentId, String transactionId, String status) {
}
