package com.mecare.authservice.utils.constants;

//  public static final String USER_LOGIN = "USER_LOGIN";
//     public static final String USER_REGISTER = "USER_REGISTER";
//     public static final String INSERT_USERS = "USER_INSERTED";
//     public static final String USER_LOGOUT = "USER_LOGOUT";
//     public static final String PASSWORD_CHANGE = "PASSWORD_CHANGE";
//     public static final String PROFILE_UPDATE = "PROFILE_UPDATE";
//     public static final String FAILED_LOGIN_ATTEMPT = "FAILED_LOGIN_ATTEMPT";
//     public static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
//     public static final String ROLE_CHANGED = "ROLE_ASSIGNED";
//     public static final String PROFILE_CREATED = "PROFILE_CREATED";
//     public static final String PROFILE_DELETED = "PROFILE_DELETED";
//     public static final String PROFILE_EDITED = "PROFILE_EDITED";

public enum AuditActionTypes {
    // Audit Action Types for Authentication and User Management
    USER_LOGIN,
    USER_REGISTER,
    INSERT_USERS,
    USER_LOGOUT,
    PASSWORD_CHANGE,
    PROFILE_UPDATE,
    FAILED_LOGIN_ATTEMPT,
    ACCOUNT_LOCKED,
    ROLE_CHANGED,
    PROFILE_CREATED,
    PROFILE_DELETED,
    PROFILE_EDITED,
    // Audit Action Types for administration
    ADMIN_CREATED,
    ADMIN_DELETED,
    ADMIN_UPDATED,
    AUDIT_ACTION_CREATED,
    AUDIT_ACTION_DELETED,
    AUDIT_ACTION_UPDATED,
    AUDIT_ACTION_RESTORED,
    AUDIT_ACTION_CATEGORY_CREATED,
    AUDIT_ACTION_CATEGORY_DELETED,
    AUDIT_ACTION_CATEGORY_UPDATED,
    AUDIT_ACTION_CATEGORY_RESTORED
}