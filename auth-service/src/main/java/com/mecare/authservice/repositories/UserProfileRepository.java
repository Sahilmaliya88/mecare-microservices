package com.mecare.authservice.repositories;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mecare.authservice.Entities.UserProfileEntity;

public interface UserProfileRepository extends JpaRepository<UserProfileEntity, UUID> {
    boolean existsByUserId(UUID userId);
}
