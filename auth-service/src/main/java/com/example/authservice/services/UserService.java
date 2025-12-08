package com.example.authservice.services;

import java.io.IOException;
import java.util.Date;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.authservice.DTOS.UserProfileRequest;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.Entities.UserProfileEntity;
import com.example.authservice.repositories.UserProfileRepository;
import com.example.authservice.repositories.UserRepository;
import com.example.authservice.utils.enums.Gender;
import com.example.authservice.utils.enums.UserRoles;
import com.example.authservice.utils.exceptions.Unauthorize;

import io.imagekit.sdk.ImageKit;
import io.imagekit.sdk.exceptions.BadRequestException;
import io.imagekit.sdk.exceptions.ForbiddenException;
import io.imagekit.sdk.exceptions.InternalServerException;
import io.imagekit.sdk.exceptions.TooManyRequestsException;
import io.imagekit.sdk.exceptions.UnauthorizedException;
import io.imagekit.sdk.exceptions.UnknownException;
import io.imagekit.sdk.models.FileCreateRequest;
import io.imagekit.sdk.models.results.Result;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {

    private final String PROFILE_FOLDER_NAME = "/profile-photos/";
    private final UserProfileRepository userProfileRepository;
    private final AuthService authService;
    private final UserRepository userRepository;

    public UserService(UserProfileRepository userProfileRepository, AuthService authService,
            UserRepository userRepository) {
        this.userProfileRepository = userProfileRepository;
        this.authService = authService;
        // Constructor implementation
        this.userRepository = userRepository;
    }

    /**
     * Create user profile
     * 
     * @param request UserProfileRequest
     * @return void
     * @throws IllegalArgumentException if other gender title is not provided when
     *                                  gender is OTHER
     */
    public void createUserProfile(UserProfileRequest request, UUID userId) {
        // other gender validation
        if (request.getGender() == Gender.OTHER
                && (request.getOtherGenderTitle() == null || request.getOtherGenderTitle().isBlank())) {
            throw new IllegalArgumentException("Other gender title must be provided when gender is OTHER");
        }

        UserEntity user;
        if (userId == null) {
            user = authService.getAuthenticatedUser();
        } else {
            UserEntity me = authService.getAuthenticatedUser();
            if (!isAdmin(me)) {
                throw new Unauthorize("Only admin can create profile for other users");
            }
            user = userRepository.findById(userId)
                    .orElseThrow(() -> new AuthService.UserNotfoundException("User not found"));
        }
        boolean exists = userProfileRepository.existsByUserId(user.getId());
        if (exists) {
            throw new IllegalStateException("User profile already exists");
        }
        Result imageResult = null;
        if (request.getFile() != null && !request.getFile().isEmpty()) {
            try {
                imageResult = uploadFileToImagekit(request.getFile(), null);
            } catch (IOException | InternalServerException | BadRequestException | UnknownException
                    | ForbiddenException | TooManyRequestsException | UnauthorizedException e) {
                log.error("Error uploading profile photo: {}", e.getMessage());
                throw new RuntimeException(e);
            }
        }
        // Logic to create user profile

        UserProfileEntity userProfile = UserProfileEntity.builder()
                .user(user)
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .dateOfBirth(Date.from(
                        request.getDateOfBirth().atStartOfDay().atZone(java.time.ZoneId.systemDefault()).toInstant()))
                .bio(request.getBio())
                .profilePictureUrl(imageResult != null ? imageResult.getUrl() : null)
                .gender(request.getGender())
                .genderOtherTitle(request.getOtherGenderTitle())
                .fileId(imageResult != null ? imageResult.getFileId() : null)
                .build();
        log.info("user profile {}", request.getFirstName());
        userProfileRepository.save(userProfile);
        log.info("User profile created for userId: {}", user.getId());
    }

    public void UploadProfilePicture(MultipartFile image, UUID userId) throws IOException, InternalServerException,
            BadRequestException, UnknownException, ForbiddenException, TooManyRequestsException, UnauthorizedException {
        UserEntity user;
        if (userId == null) {
            user = authService.getAuthenticatedUser();
        } else {
            UserEntity me = authService.getAuthenticatedUser();
            if (!isAdmin(me)) {
                throw new Unauthorize("Only admin can upload profile picture for other users");
            }
            user = userRepository.findById(userId)
                    .orElseThrow(() -> new AuthService.UserNotfoundException("User not found"));
        }
        UserProfileEntity userProfile = user.getUserProfile();
        if (userProfile == null) {
            throw new IllegalStateException("User profile does not exist");
        }
        Result imageResponse = uploadFileToImagekit(image, userProfile.getFileId());
        log.info("Image uploaded to ImageKit with URL: {}", imageResponse.getUrl());
        if (imageResponse.getUrl() != null) {
            userProfile.setProfilePictureUrl(imageResponse.getUrl());
            userProfile.setFileId(imageResponse.getFileId());
            userProfileRepository.save(userProfile);
            log.info("User profile picture updated for userId: {}", user.getId());
        } else {
            throw new RuntimeException("Failed to upload image");
        }
    }

    /**
     * Uploads a file to ImageKit and deletes the existing file if an ID is
     * provided.
     * *
     * 
     * @param file       The MultipartFile to be uploaded.
     * @param existingId The ID of the existing file to be deleted (optional).
     * @return Result The result of the file upload operation.
     * @throws UnknownException
     * @throws BadRequestException
     * @throws UnauthorizedException
     * @throws InternalServerException
     * @throws TooManyRequestsException
     * @throws ForbiddenException
     * @throws IOException
     * 
     */
    public Result uploadFileToImagekit(MultipartFile file, String existingId)
            throws ForbiddenException, TooManyRequestsException, InternalServerException, UnauthorizedException,
            BadRequestException, UnknownException, IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File must not be null or empty");
        }

        String trimmedExistingId = existingId == null ? "" : existingId.trim();
        if (!trimmedExistingId.isEmpty()) {
            ImageKit.getInstance().deleteFile(trimmedExistingId);
            log.info("Deleted existing ImageKit file with id: {}", trimmedExistingId);
        }

        byte[] bytes = file.getBytes();
        FileCreateRequest fileCreateRequest = new FileCreateRequest(bytes, file.getOriginalFilename());
        fileCreateRequest.setFolder(PROFILE_FOLDER_NAME);

        Result result = ImageKit.getInstance().upload(fileCreateRequest);
        log.info("Uploaded file to ImageKit with url: {}", result.getUrl());
        return result;
    }

    public boolean isAdmin(UserEntity user) {
        return user.getRole().equals(UserRoles.ADMIN) || user.getRole().equals(UserRoles.SUPER_ADMIN);
    }
}