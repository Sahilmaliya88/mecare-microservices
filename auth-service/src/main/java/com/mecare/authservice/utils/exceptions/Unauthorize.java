package com.mecare.authservice.utils.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class Unauthorize extends RuntimeException {
    private HttpStatus status;

    public Unauthorize(String message) {
        super(message);
    }

    public Unauthorize(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }
}
