package com.example.authservice.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authservice.Entities.AuditActions;

public interface AuditActionRepository extends JpaRepository<AuditActions, String> {

}
