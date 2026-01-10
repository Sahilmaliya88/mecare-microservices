package com.mecare.authservice.DTOS;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangePasswordRequest {
    @NotNull(message = "Old password cannot be null")
    @Schema(description = "Old password (not required for Admin or Super Admin)", defaultValue = "Test@1234")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(regexp = "^(?=.*\\d)(?=.*[^a-zA-Z0-9]).{8,20}$", message = "Password must contain at least one digit and one special character")
    private String oldPassword;
    @NotNull(message = "New password cannot be null")
    @Schema(description = "New password to update", defaultValue = "Test@1234")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    @Pattern(regexp = "^(?=.*\\d)(?=.*[^a-zA-Z0-9]).{8,20}$", message = "Password must contain at least one digit and one special character")
    private String newPassword;

    @Schema(description = "flag for whether logout from another devices of not")
    private boolean logoutFromOtherDevices;
}
