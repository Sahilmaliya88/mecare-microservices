package com.mecare.authservice.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.mecare.authservice.entities.AuditActionCategoryEntity;

public interface ActionCategoryRepository extends JpaRepository<AuditActionCategoryEntity, String> {
    @Query("SELECT a FROM AuditActionCategoryEntity a WHERE a.is_deleted = false")
    List<AuditActionCategoryEntity> findAllWhereIsDeletedFalse();
}
