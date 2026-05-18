package com.crowdsource.eventservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/event")
public class Index {

    @GetMapping("/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getIndex(){
        log.info("event-service ready");
        return ResponseEntity.ok("event-service ready");
    }

    @PostMapping("/create")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<?> createEvent(HttpServletRequest request){
        String authorization = request.getHeader("Authorization");
        String userId = request.getHeader("userId");
        log.info("Event Created userId: {} Auth: {}", userId, authorization);
        return ResponseEntity.ok("Event Created");
    }

    @GetMapping("/get")
    public ResponseEntity<String> getAllEvent(){
        log.info("event-service message");
        return ResponseEntity.ok("event-service message");
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("#id == authentication.principal.claims['userId'] or hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // Logic here
        return ResponseEntity.ok("Event Deleted");
    }

}
