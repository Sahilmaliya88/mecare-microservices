package com.example.authservice.utils;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class DeviceInfo {
    @NotNull(message = "Device ID cannot be null")
    private String deviceId;

    @NotNull(message = "Device type cannot be null")
    private String deviceType;

    @NotNull(message = "OS cannot be null")
    private String os;

    @NotNull(message = "Browser cannot be null")
    private String browser;

    @NotNull(message = "User agent cannot be null")
    private String userAgent;

}
