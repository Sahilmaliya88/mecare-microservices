package com.example.authservice.repositories;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.example.authservice.Entities.UserEntity;

import feign.Param;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {
    Optional<UserEntity> findByEmail(String email);

    @Query("select u from UserEntity u where u.password_reset_token = :token and u.password_reset_token_expires_at > :now")
    Optional<UserEntity> findByValidPasswordResetToken(@Param("token") String token, @Param("now") Date now);
}
