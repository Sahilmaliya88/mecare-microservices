package com.mecare.authservice.entities;

import java.util.Date;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.mecare.authservice.utils.enums.Gender;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Table(name = "user_profiles")
@Entity
@Data
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserProfileEntity {

    @JsonIgnore
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "org.hibernate.id.UUIDGenerator")
    private UUID id;
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonBackReference
    private UserEntity user;
    @Column(name = "first_name")
    private String firstName;
    @Column(name = "last_name")
    private String lastName;
    @Column(name = "phone_number")
    private String phoneNumber;
    @Column(name = "date_of_birth")
    private Date dateOfBirth;

    private String bio;
    @Column(name = "profile_picture_url")
    private String profilePictureUrl;
    @JsonIgnore
    @Column(name = "file_id")
    private String fileId;
    @Enumerated(EnumType.STRING)
    private Gender gender;
    @Column(name = "gender_other_title")
    private String genderOtherTitle;
    @Column(name = "created_at")
    @Builder.Default
    private Date createdAt = new Date();
    @Builder.Default
    @Column(name = "updated_at")
    private Date updatedAt = new Date();
}
