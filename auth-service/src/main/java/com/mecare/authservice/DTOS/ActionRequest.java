package com.mecare.authservice.DTOS;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ActionRequest {

    @NotBlank(message = "Code is mandatory")
    @Pattern(regexp = "^[A-Z0-9_]+$", message = "Code must be uppercase alphanumeric with underscores")
    private String code;
    @NotBlank(message = "Title is mandatory")
    private String title;
    @NotBlank(message = "Description is mandatory")
    private String description;
    @Pattern(regexp = "^[A-Z0-9_]+$", message = "Category code must be uppercase alphanumeric with underscores")
    @NotBlank(message = "Category code is mandatory")
    private String categoryCode;
}
