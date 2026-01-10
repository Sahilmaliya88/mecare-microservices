package com.mecare.authservice.DTOS;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ActionResponse {
    private String code;
    private String title;
    private String description;
    private String categoryCode;
    private boolean is_deleted;
}
