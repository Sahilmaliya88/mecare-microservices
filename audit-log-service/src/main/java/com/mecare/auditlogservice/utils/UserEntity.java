package com.mecare.auditlogservice.utils;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserEntity {
    private String id;
    private String email;
    private String role;
    private boolean verified;
    private String impersonateBy;
    private boolean isImpersonate;
    private String deviceId;

}
