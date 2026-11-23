package com.crowdsource.userservice.dto;

import java.util.UUID;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class UserResponse {
    private UUID id;
    private String email;
    private String displayName;
    private List<String> roles;
}
