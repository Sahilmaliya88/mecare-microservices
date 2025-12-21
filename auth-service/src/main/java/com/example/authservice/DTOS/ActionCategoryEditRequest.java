package com.example.authservice.DTOS;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ActionCategoryEditRequest {
    private String title;
    private String description;

}
