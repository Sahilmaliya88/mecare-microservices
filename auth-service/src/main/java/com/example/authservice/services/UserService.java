package com.example.authservice.services;

import java.io.IOException;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.authservice.DTOS.UserProfileRequest;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.Entities.UserProfileEntity;
import com.example.authservice.repositories.UserProfileRepository;
import com.example.authservice.utils.enums.Gender;

import io.imagekit.sdk.models.FileCreateRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {

    private final UserProfileRepository userProfileRepository;
    private final AuthService authService;

    public UserService(UserProfileRepository userProfileRepository, AuthService authService) {
        this.userProfileRepository = userProfileRepository;
        this.authService = authService;
        // Constructor implementation
    }

    /**
     * Create user profile
     * 
     * @param request UserProfileRequest
     * @return void
     * @throws IllegalArgumentException if other gender title is not provided when
     *                                  gender is OTHER
     */
    public void createUserProfile(UserProfileRequest request) {
        // other gender validation
        if (request.getGender() == Gender.OTHER
                && (request.getOtherGenderTitle() == null || request.getOtherGenderTitle().isBlank())) {
            throw new IllegalArgumentException("Other gender title must be provided when gender is OTHER");
        }

        UserEntity user = authService.getAuthenticatedUser();
        boolean exists = userProfileRepository.existsByUserId(user.getId());
        if (exists) {
            throw new IllegalStateException("User profile already exists");
        }
        // Logic to create user profile
        UserProfileEntity userProfile = UserProfileEntity.builder()
                .user(user)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .dateOfBirth(request.getDateOfBirth())
                .bio(request.getBio())
                .profilePictureUrl(request.getProfilePictureUrl())
                .gender(request.getGender())
                .genderOtherTitle(request.getOtherGenderTitle())
                .build();
        log.info("user profile {}", request.getFirstName());
        userProfileRepository.save(userProfile);
        log.info("User profile created for userId: {}", user.getId());
    }

    public void UploadProfilePicture(MultipartFile image) throws IOException {
        UserEntity user = authService.getAuthenticatedUser();
        if (user.getUserProfile() == null) {
            throw new IllegalStateException("User profile does not exist");
        }
        FileCreateRequest fileCreateRequest = new FileCreateRequest(image.getBytes(), image.getOriginalFilename());
    }
}
