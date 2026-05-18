package com.crowdsource.registrationservice.repository;

import com.crowdsource.registrationservice.entity.Registration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

public interface RegistrationRepository extends JpaRepository<Registration, Long> {

    @Modifying
    @Transactional
    @Query("UPDATE Registration r SET r.status = :status WHERE r.id = :id")
    int updateStatus(Long id, String status);
}
