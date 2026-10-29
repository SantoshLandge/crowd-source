package com.crowdsource.paymentservice.dto;

public record PaymentResponse(Long paymentId, String transactionId, String status) {
}
