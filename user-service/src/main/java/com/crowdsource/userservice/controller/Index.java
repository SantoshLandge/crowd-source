package com.crowdsource.userservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/user")
public class Index {

    @GetMapping("/status")
    public ResponseEntity<String> getIndex(){
        log.info("user-service ready");
        return ResponseEntity.ok("user-service ready");
    }

    @GetMapping("/message")
    public ResponseEntity<String> getMessage(){
        log.info("user-service message");
        return ResponseEntity.ok("user-service message");
    }

}
