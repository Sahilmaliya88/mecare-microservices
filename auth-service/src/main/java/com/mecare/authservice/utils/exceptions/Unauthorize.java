package com.mecare.authservice.utils.exceptions;

import org.springframework.http.HttpStatus;

import lombok.Getter;

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
