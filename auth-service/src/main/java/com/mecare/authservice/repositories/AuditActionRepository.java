package com.mecare.authservice.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.mecare.authservice.DTOS.ActionResponse;
import com.mecare.authservice.entities.AuditActions;

public interface AuditActionRepository extends JpaRepository<AuditActions, String> {
  @Query("""
          SELECT new com.mecare.authservice.DTOS.ActionResponse(
              a.code,
              a.title,
              a.description,
              c.code,
              a.is_deleted
          )
          FROM AuditActions a
          JOIN a.category c
          WHERE (:includeDeleted=true or a.is_deleted = false)
            and (:includeDeletedCategory=true or c.is_deleted = false)
            and (:categoryCodes is null or c.code in :categoryCodes)
      """)
  List<ActionResponse> findAllActiveActions(@Param("categoryCodes") String[] categoryCodes,
      @Param("includeDeletedCategory") boolean includeDeletedCategory,
      @Param("includeDeleted") boolean includeDeleted);

}
