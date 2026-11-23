package com.crowdsource.eventservice.repository;

import java.util.UUID;
import com.crowdsource.eventservice.entity.EventDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EventDetailsRepository extends JpaRepository<EventDetails, UUID> {
}
