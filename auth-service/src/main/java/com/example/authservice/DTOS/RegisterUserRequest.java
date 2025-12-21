package com.example.authservice.DTOS;

import com.example.authservice.utils.DeviceInfo;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class RegisterUserRequest {
    @NotNull(message = "Email can't be null")
    @Email(message = "Please enter a valid email")
    private String email;

    @Pattern(regexp = "^(?=.*\\d)(?=.*[^a-zA-Z0-9]).{8,20}$", message = "Password must contain at least one digit and one special character")
    @NotNull(message = "Password can't be null")
    @Size(min = 8, max = 64, message = "Password must be between 8 and 64 characters long")
    private String password;

    @NotNull(message = "Device info can't be null")
    private DeviceInfo deviceInfo;
}
