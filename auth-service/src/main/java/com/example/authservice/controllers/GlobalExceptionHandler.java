package com.example.authservice.controllers;

import com.example.authservice.services.AuthService;
import com.example.authservice.services.EmailService;
import com.example.authservice.utils.exceptions.TokenExpiredException;
import com.example.authservice.utils.exceptions.Unauthorize;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.RestClientException;
import org.yaml.snakeyaml.constructor.DuplicateKeyException;

import java.sql.SQLException;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity handleDefaultException(HttpServletRequest request,Exception e){
        return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("status",false,"message",e.getMessage()));
    }
    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<Map<String,Object>> handleNullPointerException(HttpServletRequest request,NullPointerException e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("status",false,"message",message));
    }
    @ExceptionHandler(SQLException.class)
    public ResponseEntity<Map<String, Object>> handleDuplicateKeyException(
            HttpServletRequest request, SQLException e) {
        String message = e.getCause() != null
                ? e.getCause().getMessage()
                : e.getMessage();

        return ResponseEntity.badRequest().body(
                Map.of(
                        "status", false,
                        "error", "Duplicate Key",
                        "message", message,
                        "path", request.getRequestURI()
                )
        );
    }
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<Map<String,Object>> handleTokenExpiredException(HttpServletRequest request,TokenExpiredException e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        return ResponseEntity.badRequest().body(
                Map.of(
                        "status", false,
                        "error", "Invalid token",
                        "message",message,
                        "path", request.getRequestURI()
                )
        );
    }
    @ExceptionHandler(Unauthorize.class)
    public ResponseEntity<Map<String,Object>> handleUnAuthorizeException(HttpServletRequest request,Unauthorize e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        HttpStatus status = e.getStatus() != null ? e.getStatus():HttpStatus.UNAUTHORIZED;
        return ResponseEntity.status(status).body(
                Map.of(
                        "status", false,
                        "error", "Unauthorized",
                        "message",message,
                        "path", request.getRequestURI()
                )
        );
    }
    @ExceptionHandler(AuthService.AlreadyVerifiedException.class)
    public ResponseEntity<Map<String,Object>> handleAlreadyVerifiedException(HttpServletRequest request, AuthService.AlreadyVerifiedException e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                Map.of(
                        "status", false,
                        "error", "Already Verified",
                        "message",message,
                        "path", request.getRequestURI()
                )
        );
    }
    @ExceptionHandler(AuthService.UserNotfoundException.class)
    public ResponseEntity<Map<String,Object>> handleUserNotFound(HttpServletRequest request, AuthService.UserNotfoundException e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                Map.of(
                        "status", false,
                        "error", "User not found!",
                        "message",message,
                        "path", request.getRequestURI()
                )
        );
    }
    @ExceptionHandler(EmailService.EmailSendingException.class)
    public ResponseEntity<Map<String,Object>> handleEmailSendingException(HttpServletRequest request, EmailService.EmailSendingException e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                Map.of(
                        "status", false,
                        "error", "Failed to send email!",
                        "message",message,
                        "path", request.getRequestURI()
                )
        );
    }
    @ExceptionHandler(AuthService.InvalidLoginTypeException.class)
    public ResponseEntity<Map<String,Object>> handleInvalidLoginTypeException(HttpServletRequest request, AuthService.InvalidLoginTypeException e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                Map.of(
                        "status", false,
                        "error", "Invalid login type!",
                        "message",message,
                        "path", request.getRequestURI()
                )
        );
    }
    @ExceptionHandler(RestClientException.class)
    public ResponseEntity<Map<String,Object>> handleRestClientException(HttpServletRequest request, RestClientException e){
        String message = e.getCause() != null ? e.getCause().getMessage():e.getMessage();
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                Map.of(
                        "status", false,
                        "error", "Failed to fetch data!",
                        "message",message,
                        "path", request.getRequestURI()
                )
        );
    }
}
