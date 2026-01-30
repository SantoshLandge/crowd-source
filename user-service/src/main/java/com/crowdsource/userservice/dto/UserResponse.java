package com.crowdsource.userservice.dto;


import com.crowdsource.userservice.entity.type.Role;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserResponse {
    private Long id;
    private String username;
    private String email;
    private Role role;

}
