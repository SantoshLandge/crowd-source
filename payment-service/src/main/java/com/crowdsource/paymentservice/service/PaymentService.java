package com.crowdsource.paymentservice.service;

import com.crowdsource.paymentservice.dto.PaymentResponse;
import com.crowdsource.paymentservice.entity.Payment;
import com.crowdsource.paymentservice.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PaymentService {

    public static final String SUCCESS = "SUCCESS";
    public static final String FAILED = "FAILED";
    public static final String REFUNDED = "REFUNDED";

    private final PaymentRepository paymentRepository;

    /** Idempotent per registration: a retry returns the already successful payment instead of charging twice. */
    @Transactional
    public PaymentResponse processPayment(String registrationId, BigDecimal amount) {
        Optional<Payment> existing = paymentRepository.findFirstByRegistrationIdOrderByIdDesc(registrationId);
        if (existing.isPresent() && SUCCESS.equals(existing.get().getStatus())) {
            return toResponse(existing.get());
        }

        log.info("Processing payment for registration {}, amount {}", registrationId, amount);

        Payment payment = new Payment();
        payment.setRegistrationId(registrationId);
        payment.setAmount(amount);
        payment.setTransactionId("TXN-" + UUID.randomUUID());
        payment.setPaymentDate(LocalDateTime.now());
        payment.setStatus(simulatePaymentGateway() ? SUCCESS : FAILED);

        // A failed payment is a normal business result: persist it and report it (no exception => no rollback)
        return toResponse(paymentRepository.save(payment));
    }

    @Transactional
    public PaymentResponse processRefund(Long paymentId) {
        Payment payment = paymentRepository.findById(paymentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Payment not found"));

        if (REFUNDED.equals(payment.getStatus())) {
            return toResponse(payment);   // idempotent
        }
        if (!SUCCESS.equals(payment.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Only successful payments can be refunded");
        }
        payment.setStatus(REFUNDED);
        log.info("Payment {} refunded", paymentId);
        return toResponse(paymentRepository.save(payment));
    }

    private PaymentResponse toResponse(Payment p) {
        return new PaymentResponse(p.getId(), p.getTransactionId(), p.getStatus());
    }

    private boolean simulatePaymentGateway() {
        // Always succeeds for the demo; replace with a real Stripe/PayPal call.
        return true;
    }
}
