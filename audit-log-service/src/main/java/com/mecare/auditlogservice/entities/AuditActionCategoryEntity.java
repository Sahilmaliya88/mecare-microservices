
package com.mecare.auditlogservice.entities;

import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name = "audit_action_categories")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class AuditActionCategoryEntity {
    @Id
    private String code;
    private String title;
    private String description;
    @Builder.Default
    @JsonIgnore
    private boolean is_deleted = false;
    @Builder.Default
    @JsonIgnore
    private Date created_at = new Date();
    @JsonBackReference
    @JsonIgnore
    @OneToMany(mappedBy = "category", fetch = FetchType.LAZY, orphanRemoval = true, cascade = CascadeType.ALL)
    private List<AuditActions> auditActions;
}