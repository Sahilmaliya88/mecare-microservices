package com.mecare.auditlogservice.entities;

import java.util.Date;
import java.util.UUID;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.ToString;

// CREATE TABLE audit_logs (
//   id UUID PRIMARY KEY,
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

//   FOREIGN KEY (action_type_code) REFERENCES audit_action_types(code)
// );

@Entity
@Table(name = "audit_logs")
@Data
@Builder
@ToString
public class AuditLogEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    private UUID actor_id;
    private String actor_type;
    private UUID target_id;
    private String target_type;
    // private String action_type_code;
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "action_type_code", referencedColumnName = "code", nullable = false)
    private AuditActions action_type;
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "action_category_code", referencedColumnName = "code", nullable = false)
    private AuditActionCategoryEntity action_category;
    // private String action_category_code;
    private String impersonated_user_id;
    private String previous_data;
    private String new_data;
    private String ip_address;
    private String user_agent;
    private String source_device;
    @Builder.Default
    private Date created_at = new Date();
}
