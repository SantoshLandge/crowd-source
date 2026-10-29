package com.crowdsource.eventservice.repository;

import com.crowdsource.eventservice.entity.Event;
import com.crowdsource.eventservice.entity.type.EventStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public interface EventRepository extends JpaRepository<Event, Long> {

    List<Event> findByStatusOrderByEventDateAsc(EventStatus status);

    List<Event> findByOrganizerIdOrderByEventDateAsc(Long organizerId);

    /** Atomic decrement; returns 0 when there is not enough capacity (no overselling under concurrency). */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query("UPDATE Event e SET e.availableCapacity = e.availableCapacity - :quantity " +
            "WHERE e.id = :eventId AND e.status = com.crowdsource.eventservice.entity.type.EventStatus.LIVE " +
            "AND e.availableCapacity >= :quantity")
    int reduceCapacity(@Param("eventId") Long eventId, @Param("quantity") int quantity);

    /** Atomic increment, never beyond the total capacity. Returns 0 if that would exceed it. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query("UPDATE Event e SET e.availableCapacity = e.availableCapacity + :quantity " +
            "WHERE e.id = :eventId AND e.availableCapacity + :quantity <= e.totalCapacity")
    int increaseCapacity(@Param("eventId") Long eventId, @Param("quantity") int quantity);
}
