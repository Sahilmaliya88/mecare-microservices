package com.mecare.authservice.utils.enums;

import lombok.Getter;

@Getter
public enum AuthAuditActions {
        USER_REGISTER(
                        "User Registration",
                        "New user registered using email and password"),
        USER_LOGIN(
                        "User Login",
                        "User logged in using email and password"),
        SOCIAL_LOGIN(
                        "Social Login",
                        "User logged in using social authentication provider"),
        LOGIN_FAILED(
                        "Login Failed",
                        "Failed login attempt due to invalid credentials"),

        // Profile & Verification
        VERIFY_USER(
                        "Verify User Account",
                        "User profile verification completed"),
        SEND_VERIFICATION_CODE(
                        "Send Verification Code",
                        "Verification code sent to user email or phone"),
        FORGOT_PASSWORD_REQUEST(
                        "Forgot Password Request",
                        "User requested password reset"),
        RESET_PASSWORD(
                        "Reset Password",
                        "User reset password using reset token"),
        CHANGE_PASSWORD(
                        "Change Password",
                        "User changed account password"), // Role & Authorization
        CHANGE_USER_ROLE(
                        "Change User Role",
                        "User role was changed"),

        UNAUTHORIZED_ACCESS(
                        "Unauthorized Access Attempt",
                        "User attempted to access a protected resource without permission"),

        // Impersonation
        START_IMPERSONATION(
                        "Start User Impersonation",
                        "Admin started impersonating another user"),

        END_IMPERSONATION(
                        "End User Impersonation",
                        "Admin stopped impersonating another user"), // Account Lifecycle
        DELETE_USER(
                        "Delete User Account",
                        "User account was deleted"),

        USER_LOGOUT(
                        "User Logout",
                        "User logged out from the system"),
                        ;

        private final String title;
        private final String description;

        AuthAuditActions(String title, String description) {
                this.title = title;
                this.description = description;
        }

        public String getActionCategoryCode() {
                return "AUTHENTICATION";
        }
}
