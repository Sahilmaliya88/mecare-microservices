package com.example.authservice.controllers;

import java.sql.SQLException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.RestClientException;

import com.example.authservice.services.AuthService;
import com.example.authservice.services.EmailService;
import com.example.authservice.services.UserService;
import com.example.authservice.utils.exceptions.TokenExpiredException;
import com.example.authservice.utils.exceptions.Unauthorize;

import jakarta.servlet.http.HttpServletRequest;

@ControllerAdvice
public class GlobalExceptionHandler {
        @ExceptionHandler(Exception.class)
        public ResponseEntity handleDefaultException(HttpServletRequest request, Exception e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                                Map.of(
                                                "status", false,
                                                "error", "Unexpected error!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(NullPointerException.class)
        public ResponseEntity<Map<String, Object>> handleNullPointerException(HttpServletRequest request,
                        NullPointerException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                                Map.of(
                                                "status", false,
                                                "error", "null pointer!",
                                                "message", message,
                                                "path", request.getRequestURI()));
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
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(TokenExpiredException.class)
        public ResponseEntity<Map<String, Object>> handleTokenExpiredException(HttpServletRequest request,
                        TokenExpiredException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.badRequest().body(
                                Map.of(
                                                "status", false,
                                                "error", "Invalid token",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(Unauthorize.class)
        public ResponseEntity<Map<String, Object>> handleUnAuthorizeException(HttpServletRequest request,
                        Unauthorize e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                HttpStatus status = e.getStatus() != null ? e.getStatus() : HttpStatus.UNAUTHORIZED;
                return ResponseEntity.status(status).body(
                                Map.of(
                                                "status", false,
                                                "error", "Unauthorized",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(AuthService.AlreadyVerifiedException.class)
        public ResponseEntity<Map<String, Object>> handleAlreadyVerifiedException(HttpServletRequest request,
                        AuthService.AlreadyVerifiedException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                                Map.of(
                                                "status", false,
                                                "error", "Already Verified",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(AuthService.UserNotfoundException.class)
        public ResponseEntity<Map<String, Object>> handleUserNotFound(HttpServletRequest request,
                        AuthService.UserNotfoundException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                                Map.of(
                                                "status", false,
                                                "error", "User not found!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(EmailService.EmailSendingException.class)
        public ResponseEntity<Map<String, Object>> handleEmailSendingException(HttpServletRequest request,
                        EmailService.EmailSendingException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                                Map.of(
                                                "status", false,
                                                "error", "Failed to send email!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(AuthService.InvalidLoginTypeException.class)
        public ResponseEntity<Map<String, Object>> handleInvalidLoginTypeException(HttpServletRequest request,
                        AuthService.InvalidLoginTypeException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                                Map.of(
                                                "status", false,
                                                "error", "Invalid login type!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(RestClientException.class)
        public ResponseEntity<Map<String, Object>> handleRestClientException(HttpServletRequest request,
                        RestClientException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                                Map.of(
                                                "status", false,
                                                "error", "Failed to fetch data!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(AuthService.SameUserException.class)
        public ResponseEntity<Map<String, Object>> handleSameUserException(HttpServletRequest request,
                        AuthService.SameUserException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                                Map.of(
                                                "status", false,
                                                "error", "Same user found!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(UserService.UserProfileNotfoundException.class)
        public ResponseEntity<Map<String, Object>> handleUserProfileNotFoundException(HttpServletRequest request,
                        UserService.UserProfileNotfoundException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                                Map.of(
                                                "status", false,
                                                "error", "User profile not found!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(UserService.UserProfileAlreadyExistsException.class)
        public ResponseEntity<Map<String, Object>> handleUserProfileAlreadyExistsException(HttpServletRequest request,
                        UserService.UserProfileAlreadyExistsException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                                Map.of(
                                                "status", false,
                                                "error", "User profile already exists!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }

        @ExceptionHandler(UserService.ProfilePictureException.class)
        public ResponseEntity<Map<String, Object>> handleProfilePictureException(HttpServletRequest request,
                        UserService.ProfilePictureException e) {
                String message = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                                Map.of(
                                                "status", false,
                                                "error", "Profile picture upload failed!",
                                                "message", message,
                                                "path", request.getRequestURI()));
        }
}
