package com.example.authservice.Entities;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.example.authservice.utils.LoginProviders;
import com.example.authservice.utils.UserRoles;
import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Table(name = "users")
@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserEntity {
    // uuid
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "org.hibernate.id.UUIDGenerator")
    private UUID id;
    // email
    @Column(unique = true)
    private String email;
    // hashed password
    @JsonIgnore
    private String password;
    // status
    @Builder.Default
    private Boolean isActive = true;
    // created_at
    @Builder.Default
    @JsonIgnore
    private Date created_at = new Date();
    // updated_at
    @JsonIgnore
    private Date updated_at;
    // deleted_at
    @JsonIgnore
    private Date deleted_at;
    @Builder.Default
    private Boolean is_verified = false;
    // token-version
    @JsonIgnore
    private String verification_code;
    @JsonIgnore
    private Date verification_code_expires_at;
    @JsonIgnore
    private String password_reset_token;
    @JsonIgnore
    private Date password_reset_token_expires_at;
    @JsonIgnore
    @Transient
    private String token_version;
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private UserRoles role = UserRoles.USER;
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private LoginProviders provider = LoginProviders.EMAIL;
    @JsonIgnore
    @Column(columnDefinition = "provider_id")
    private String providerId;
    // login sessions
    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY, orphanRemoval = true, cascade = jakarta.persistence.CascadeType.ALL)
    private List<LoginSessionEntity> loginSessions;
}
