package com.example.authservice.repositories;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.example.authservice.DTOS.UsersResponse;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.utils.LoginProviders;
import com.example.authservice.utils.UserRoles;

import feign.Param;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {
    Optional<UserEntity> findByEmail(String email);

    @Query("select u from UserEntity u where u.password_reset_token = :token and u.password_reset_token_expires_at > :now")
    Optional<UserEntity> findByValidPasswordResetToken(@Param("token") String token, @Param("now") Date now);

    @Query("SELECT new com.example.authservice.DTOS.UsersResponse(u.id, u.email, u.role, u.is_verified, u.provider) "
            + "FROM UserEntity u "
            + "WHERE (:search IS NULL OR LOWER(u.email) LIKE LOWER(CONCAT('%', :search,'%'))) "
            + "AND (:role IS NULL OR u.role = :role) "
            + "AND (:isVerified IS NULL OR u.is_verified = :isVerified)"
            + "AND (:isActive IS NULL OR u.isActive = :isActive)"
            + "AND (:provider IS NULL OR u.provider = :provider)")
    Page<UsersResponse> findByFilters(@Param("search") String search, @Param("role") UserRoles role,
            @Param("isActive") Boolean isActive, @Param("isVerified") Boolean isVerified,
            @Param("provider") LoginProviders provider,
            Pageable pageable);
}
