package com.crowdsource.registrationservice.repository;

import java.util.UUID;
import com.crowdsource.registrationservice.entity.Registration;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RegistrationRepository extends JpaRepository<Registration, UUID> {
    List<Registration> findByUserIdOrderByCreatedAtDesc(UUID userId);
}
