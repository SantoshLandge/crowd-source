package com.crowdsource.eventservice.repo;

import com.crowdsource.eventservice.entity.Event;
import com.crowdsource.eventservice.entity.type.EventStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface EventRepository extends JpaRepository<Event, Long> {
    List<Event> findByStatus(EventStatus status);

    @Query("SELECT e FROM Event e WHERE e.status = :status AND e.startAt >= :date")
    List<Event> searchLiveEvents(@Param("status") EventStatus status, @Param("date") LocalDateTime date);

    Optional<Event> findByIdAndOrganizerId(Long id, Long organizerId);
}
