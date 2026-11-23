package com.crowdsource.paymentservice.repository;

import java.util.UUID;
import com.crowdsource.paymentservice.entity.Payment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PaymentRepository extends JpaRepository<Payment, UUID> {
    Optional<Payment> findFirstByRegistrationIdOrderByIdDesc(UUID registrationId);
}
