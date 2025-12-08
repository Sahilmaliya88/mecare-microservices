package com.example.authservice.DTOS;

import java.time.LocalDate;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.multipart.MultipartFile;

import com.example.authservice.utils.enums.Gender;
import com.fasterxml.jackson.annotation.JsonFormat;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;

@Builder
@Data
@ToString
public class UserProfileRequest {

    @Schema(description = "First name of user", example = "John")
    @NotBlank(message = "First name cannot be blank")
    private String firstName;
    @Schema(description = "Last name of user", example = "Doe")
    @NotBlank(message = "Last name cannot be blank")
    private String lastName;
    @NotBlank(message = "Phone number cannot be blank")
    @Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Invalid phone number format")
    private String phoneNumber;
    @NotNull(message = "Date of birth cannot be null")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) // for form-data / @ModelAttribute
    @JsonFormat(pattern = "yyyy-MM-dd") // for JSON / @RequestBody
    private LocalDate dateOfBirth;
    private String bio;
    private String profilePictureUrl;
    @NotNull(message = "Gender cannot be null")
    private Gender gender;
    private String otherGenderTitle;
    private MultipartFile file;
}
