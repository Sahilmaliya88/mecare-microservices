package com.example.authservice.DTOS;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ActionEditRequest {
    @Schema(description = "Title of the action", example = "Update User Profile")
    private String title;
    @Schema(description = "Description of the action", example = "Allows users to modify their personal information.")
    private String description;
}
