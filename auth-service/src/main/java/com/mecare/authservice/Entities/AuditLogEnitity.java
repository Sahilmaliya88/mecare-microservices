package com.mecare.authservice.Entities;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.mecare.authservice.utils.constants.AuditActionCategories;
import com.mecare.authservice.utils.enums.UserRoles;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;

//  id UUID PRIMARY KEY,
//   actor_id UUID NOT NULL,
//   actor_type varchar(50) NOT NULL,
//   target_id UUID,
//   target_type varchar(50) Not NULL,
//   action_type_code varchar(50) NOT NULL,
// action_category_code varchar(50) NOT NULL,
//   impersonated_user_id UUID,
//   previous_data JSONB,
//   new_data JSONB,
//     ip_address VARCHAR(45),
//     user_agent TEXT,
//     source_device VARCHAR(255),
//     created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
@Entity
@Table(name = "audit_logs")
@Data
public class AuditLogEnitity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "org.hibernate.id.UUIDGenerator")
    private UUID id;
    private UUID actorId;
    @Enumerated(EnumType.STRING)
    private UserRoles actorType;
    private UUID targetId;
    @Enumerated(EnumType.STRING)
    private UUID targetType;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "action_type_code", nullable = false)
    private AuditActions actionType;
    @Enumerated(EnumType.STRING)
    private AuditActionCategories actionCategoryCode;
    private UUID impersonatedUserId;
    private Map<String, Object> previousData;
    private Map<String, Object> newData;
    private String ipAddress;
    private String userAgent;
    private String sourceDevice;
    private Date createdAt;
}
