package com.mecare.authservice.repositories;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.mecare.authservice.entities.LoginSessionEntity;
import com.mecare.authservice.entities.UserEntity;

import jakarta.transaction.Transactional;

public interface SessionRepository extends JpaRepository<LoginSessionEntity, UUID> {
    Optional<LoginSessionEntity> findByUserAndDeviceIdAndIsActive(UserEntity user, String deviceId, boolean isActive);

    @Transactional
    void deleteAllByUser(UserEntity user);

    @Transactional
    @Modifying
    @Query("UPDATE LoginSessionEntity s SET s.isActive = false WHERE s.user = ?1 AND s.deviceId = ?2")
    int deActiveSessionByUserAndDeviceId(UserEntity user, String deviceId);

    @Transactional
    @Modifying
    @Query("UPDATE LoginSessionEntity s SET s.isActive = false WHERE s.user = ?1")
    int deActiveSessionByUser(UserEntity user);
}
