package com.example.authservice.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authservice.Entities.AuditActionCategoryEntity;

public interface ActionCategoryRepository extends JpaRepository<AuditActionCategoryEntity, String> {

}
