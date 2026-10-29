package com.crowdsource.userservice.dto;

import com.crowdsource.userservice.entity.enums.UserStatus;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateUserStatusRequest {

    @NotNull
    private UserStatus status;
}
