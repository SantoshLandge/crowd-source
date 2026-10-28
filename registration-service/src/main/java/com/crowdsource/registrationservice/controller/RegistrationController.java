package com.crowdsource.registrationservice.controller;

import com.crowdsource.registrationservice.dto.RegistrationRequest;
import com.crowdsource.registrationservice.entity.Registration;
import com.crowdsource.registrationservice.repository.RegistrationRepository;
import com.crowdsource.registrationservice.service.RegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/registration")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;
    private final RegistrationRepository registrationRepository;

    @PostMapping
    public ResponseEntity<Registration> register(@RequestBody RegistrationRequest request) {
        return ResponseEntity.ok(registrationService.register(request));
    }

    @GetMapping
    public List<Registration> getAll() {
        return registrationRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Registration> getById(@PathVariable Long id) {
        return registrationRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/cancel")
    public ResponseEntity<Void> cancel(@PathVariable Long id) {
        registrationService.cancelRegistration(id);
        return ResponseEntity.ok().build();
    }
}
