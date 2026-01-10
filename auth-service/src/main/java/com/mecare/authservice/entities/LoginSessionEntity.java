package com.mecare.authservice.entities;

import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Table(name = "login_sessions")
@Entity
@Data
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class LoginSessionEntity {

    @Id
    @GeneratedValue(strategy = jakarta.persistence.GenerationType.AUTO, generator = "org.hibernate.id.UUIDGenerator")
    private UUID id;
    @JsonBackReference
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "device_id", nullable = false)
    private String deviceId;
    @JsonIgnore
    @Column(name = "token_version", nullable = false)
    private String tokenVersion;
    @Column(name = "ip_address", nullable = false)
    private String ipAddress;
    @Column(name = "user_agent", columnDefinition = "TEXT", nullable = false)
    private String userAgent;
    private String os;
    private String browser;
    @Column(name = "device_type")
    private String deviceType;
    @Builder.Default
    @Column(name = "created_at")
    private java.util.Date createdAt = new java.util.Date();
    @Builder.Default
    @Column(name = "last_used_at")
    private java.util.Date lastUsedAt = new java.util.Date();
    @Builder.Default
    @Column(name = "is_active")
    private Boolean isActive = true;
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "actual_session_id", referencedColumnName = "id")
    @JsonBackReference
    private LoginSessionEntity actualSession;
    @ManyToOne(fetch = FetchType.EAGER)
    @JsonBackReference
    @JoinColumn(name = "impersonated_by", referencedColumnName = "id")
    private UserEntity impersonatedBy;
}
