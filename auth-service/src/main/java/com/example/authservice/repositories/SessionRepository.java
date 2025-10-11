package com.example.authservice.repositories;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authservice.Entities.LoginSessionEntity;
import com.example.authservice.Entities.UserEntity;

import jakarta.transaction.Transactional;

public interface SessionRepository extends JpaRepository<LoginSessionEntity, UUID> {
    Optional<LoginSessionEntity> findByUserAndDeviceId(UserEntity user, String deviceId);

    @Transactional
    void deleteAllByUser(UserEntity user);
}
