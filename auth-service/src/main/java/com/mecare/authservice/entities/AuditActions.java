package com.mecare.authservice.entities;

import java.util.Date;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "audit_action_types")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditActions {

    @Id
    private String code;
    private String title;
    private String description;
    @Builder.Default
    private boolean is_deleted = false;
    @Builder.Default
    private Date created_at = new Date();
    @ManyToOne
    private AuditActionCategoryEntity category;
}
