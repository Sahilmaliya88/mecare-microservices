package com.mecare.authservice.DTOS;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuditEvent {
    private String type;
    private String message;
    private String data;
    private String timestamp;
}
