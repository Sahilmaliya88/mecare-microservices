package com.mecare.authservice.services;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.mecare.authservice.entities.UserEntity;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for sending emails, such as welcome messages and verification codes,
 * using Thymeleaf templates.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender javaMailSender;
    private final TemplateEngine templateEngine;
    @Value("${spring.environments.app-url}")
    private String appUrl;

    @Value("${spring.mail.from-address}")
    private String fromEmail;

    /**
     * Sends a welcome email to the specified user with a verification code.
     *
     * @param user the {@link UserEntity} to send the email to
     * @throws IllegalArgumentException if the user or required fields are null
     * @throws EmailSendingException    if an error occurs while sending the email
     */
    @Async
    public void sendWelcomeEmail(UserEntity user) {
        validateUser(user);
        Context context = new Context();
        context.setVariable("email", user.getEmail());
        context.setVariable("otp", user.getVerification_code());
        sendEmail(user, "VerificationCode", "Verification Code", context);
        sendEmail(user, "Welcome", "Welcome Message", context);
    }

    /**
     * Sends a password reset link email to the specified user.
     *
     * @param user the {@link UserEntity} to send the email to
     * @throws IllegalArgumentException if the user, email, or password reset token
     *                                  is null or invalid
     * @throws EmailSendingException    if an error occurs while sending the email
     */
    @Async
    public void sendPasswordResetLink(UserEntity user) {
        String passwordResetPath = "/reset-password";
        validateUser(user);
        Objects.requireNonNull(user.getPassword_reset_token(), "Password reset token cannot be null");
        if (user.getPassword_reset_token().isBlank()) {
            throw new IllegalArgumentException("Password reset token cannot be empty");
        }

        log.info("Preparing to send password reset link to {}", user.getEmail());

        String passwordResetLink = appUrl + passwordResetPath + "/" + user.getPassword_reset_token();
        Context context = new Context();
        context.setVariable("email", user.getEmail());
        context.setVariable("resetLink", passwordResetLink);
        context.setVariable("appUrl", appUrl);

        sendEmail(user, "password-reset", "Password Reset Request", context);
    }

    /**
     * Sends a verification code email to the specified user.
     *
     * @param user the {@link UserEntity} to send the email to
     * @throws IllegalArgumentException if the user or required fields are null
     * @throws EmailSendingException    if an error occurs while sending the email
     */
    @Async
    public void sendVerificationCodeEmail(UserEntity user) {
        validateUser(user);
        Context context = new Context();
        context.setVariable("email", user.getEmail());
        context.setVariable("otp", user.getVerification_code());
        sendEmail(user, "VerificationCode", "Verification Code", context);
    }

    /**
     * Validates the user entity and its required fields.
     *
     * @param user the {@link UserEntity} to validate
     * @throws IllegalArgumentException if the user or required fields are null
     */
    private void validateUser(UserEntity user) {
        Objects.requireNonNull(user, "User entity cannot be null");
        Objects.requireNonNull(user.getEmail(), "User email cannot be null");
        if (user.getEmail().isBlank()) {
            throw new IllegalArgumentException("User email cannot be empty");
        }
    }

    /**
     * Sends an email using the specified template and subject.
     *
     * @param user     the {@link UserEntity} to send the email to
     * @param template the Thymeleaf template name
     * @param subject  the email subject
     * @param context  the template context according to template
     * @throws EmailSendingException if an error occurs while sending the email
     */
    private void sendEmail(UserEntity user, String template, String subject, Context context) {
        try {
            log.info("Preparing to send email to {} with template {}", user.getEmail(), template);

            String parsedTemplate = templateEngine.process(template, context);

            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(fromEmail);
            helper.setTo(user.getEmail());
            helper.setSubject(subject);
            helper.setText(parsedTemplate, true);

            javaMailSender.send(message);
            log.info("Successfully sent email to {}", user.getEmail());
        } catch (MessagingException e) {
            log.error("Failed to send email to {}: {}", user.getEmail(), e.getMessage(), e);
            throw new EmailSendingException("Failed to send email to " + user.getEmail(), e);
        }
    }

    /**
     * Custom exception for email sending failures.
     */
    public static class EmailSendingException extends RuntimeException {
        public EmailSendingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}