package com.crowdsource.paymentservice.service;

import com.crowdsource.paymentservice.entity.Payment;
import com.crowdsource.paymentservice.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class PaymentService {

    private final PaymentRepository paymentRepository;

    public String processPayment(String registrationId, BigDecimal amount) {
        log.info("Processing payment for registration: {}, amount: {}", registrationId, amount);

        // Simulate payment gateway call
        String transactionId = "TXN-" + System.currentTimeMillis();
        boolean paymentSuccess = simulatePaymentGateway();

        Payment payment = new Payment();
        payment.setRegistrationId(registrationId);
        payment.setAmount(amount);
        payment.setTransactionId(transactionId);
        payment.setPaymentDate(LocalDateTime.now());

        if (paymentSuccess) {
            payment.setStatus("SUCCESS");
            paymentRepository.save(payment);
            log.info("Payment successful: {}", payment.getId());
            return payment.getId().toString();
        } else {
            payment.setStatus("FAILED");
            paymentRepository.save(payment);
            throw new RuntimeException("Payment gateway failed");
        }
    }

    public void processRefund(Long paymentId) {
        log.info("Processing refund for payment: {}", paymentId);

        Payment payment = paymentRepository.findById(paymentId).orElseThrow();
        payment.setStatus("REFUNDED");
        paymentRepository.save(payment);

        log.info("Refund processed successfully");
    }

    private boolean simulatePaymentGateway() {
        // Always return true for demo
        // In real scenario, this would call Stripe/PayPal
        return true;
    }
}
