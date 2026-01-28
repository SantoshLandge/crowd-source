package com.crowdsource.eventservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/event")
public class Index {

    @GetMapping("/status")
    public ResponseEntity<String> getIndex(){
        log.info("event-service ready");
        return ResponseEntity.ok("event-service ready");
    }

    @GetMapping("/message")
    public ResponseEntity<String> getMessage(){
        log.info("event-service message");
        return ResponseEntity.ok("event-service message");
    }

}
