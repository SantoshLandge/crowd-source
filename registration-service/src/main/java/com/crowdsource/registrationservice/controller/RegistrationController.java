package com.crowdsource.registrationservice.controller;

import com.crowdsource.registrationservice.dto.RegistrationRequest;
import com.crowdsource.registrationservice.dto.RegistrationResponse;
import com.crowdsource.registrationservice.service.RegistrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** Reached through the gateway as /api/v1/registration/** (StripPrefix=1). */
@RestController
@RequestMapping("/v1/registration")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
public class RegistrationController {

    private final RegistrationService service;

    @PostMapping
    public ResponseEntity<RegistrationResponse> register(@Valid @RequestBody RegistrationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.register(request));
    }

    @GetMapping("/mine")
    public List<RegistrationResponse> mine() {
        return service.myRegistrations();
    }

    @GetMapping("/{id}")
    public RegistrationResponse get(@PathVariable Long id) {
        return service.get(id);
    }

    @PostMapping("/{id}/cancel")
    public RegistrationResponse cancel(@PathVariable Long id) {
        return service.cancel(id);
    }
}
