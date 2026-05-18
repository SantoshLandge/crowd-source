package com.crowdsource.paymentservice.repository;

import com.crowdsource.paymentservice.entity.Payment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
    Payment findByRegistrationId(String registrationId);
}
