package com.crowdsource.eventservice.repo;

import com.crowdsource.eventservice.entity.EventDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EventDetailsRepository extends JpaRepository<EventDetails, Long> {
}