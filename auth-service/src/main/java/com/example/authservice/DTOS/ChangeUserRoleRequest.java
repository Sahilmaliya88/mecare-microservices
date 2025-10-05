package com.example.authservice.DTOS;

import com.example.authservice.utils.UserRoles;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ChangeUserRoleRequest {
    @Email(message = "Invalid email format. Please provide a valid email address.")
    @NotBlank(message = "Email is required and cannot be blank.")
    @Size(max = 100, message = "Email must not exceed 100 characters.")
    @Schema(description = "Email of user whose role you want to change",defaultValue = "johndoe@gmail.com")
    private String email;
    @Schema(description = "Role which you change to user",defaultValue = "USER")
    @NotNull(message = "User role is required. Allowed values are: ADMIN, USER, DOCTOR, TEAM_MEMBER.")
    private UserRoles userRole;
}
