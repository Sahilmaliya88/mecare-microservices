package com.example.authservice.repositories;

import com.example.authservice.Entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserEntity,UUID> {
    Optional<UserEntity> findByEmail(String email);
}
