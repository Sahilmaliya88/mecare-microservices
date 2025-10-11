package com.example.authservice.repositories;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authservice.Entities.LoginSessionEntity;

public interface SessionRepository extends JpaRepository<LoginSessionEntity, UUID> {

}
