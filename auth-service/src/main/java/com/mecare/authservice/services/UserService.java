package com.mecare.authservice.services;

import java.io.IOException;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.mecare.authservice.DTOS.UserProfileRequest;
import com.mecare.authservice.entities.UserEntity;
import com.mecare.authservice.entities.UserProfileEntity;
import com.mecare.authservice.repositories.UserProfileRepository;
import com.mecare.authservice.repositories.UserRepository;
import com.mecare.authservice.utils.enums.Gender;
import com.mecare.authservice.utils.enums.UserRoles;
import com.mecare.authservice.utils.exceptions.Unauthorize;

import io.imagekit.sdk.ImageKit;
import io.imagekit.sdk.exceptions.BadRequestException;
import io.imagekit.sdk.exceptions.ForbiddenException;
import io.imagekit.sdk.exceptions.InternalServerException;
import io.imagekit.sdk.exceptions.TooManyRequestsException;
import io.imagekit.sdk.exceptions.UnauthorizedException;
import io.imagekit.sdk.exceptions.UnknownException;
import io.imagekit.sdk.models.FileCreateRequest;
import io.imagekit.sdk.models.results.Result;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {
    private static long MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB
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
    @Transactional
    public void createUserProfile(UserProfileRequest request, UUID userId) {
        // other gender validation
        if (request.getGender() == Gender.OTHER
                && (request.getOtherGenderTitle() == null || request.getOtherGenderTitle().isBlank())) {
            throw new IllegalArgumentException("Other gender title must be provided when gender is OTHER");
        }

        UserEntity user = getUserForOperation(userId);
        boolean exists = userProfileRepository.existsByUserId(user.getId());
        if (exists) {
            throw new UserProfileAlreadyExistsException("User profile already exists");
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

    /**
     * Update user profile
     * 
     * @param request UserProfileRequest
     * @return void
     * @throws UserProfileNotfoundException if user profile not found
     */
    @Transactional
    public void updateUserProfile(UserProfileRequest request, UUID userId) {
        // Implementation for updating user profile
        UserEntity user = getUserForOperation(userId);
        UserProfileEntity userProfile = user.getUserProfile();
        if (userProfile == null) {
            throw new UserProfileNotfoundException("User profile does not exist");
        }
        // upload new file if provided
        if (request.getFile() != null && !request.getFile().isEmpty()) {
            try {
                Result uploadFileResponse = uploadFileToImagekit(request.getFile(), userProfile.getFileId());
                userProfile.setProfilePictureUrl(uploadFileResponse.getUrl());
                userProfile.setFileId(uploadFileResponse.getFileId());
            } catch (ForbiddenException | TooManyRequestsException | InternalServerException | UnauthorizedException
                    | BadRequestException | UnknownException | IOException e) {
                log.error("error occured in update profile", e.getMessage());
                throw new ProfilePictureException(e.getMessage(), e);
            }
        }
        Optional.ofNullable(request.getFirstName()).ifPresent(userProfile::setFirstName);
        Optional.ofNullable(request.getLastName()).ifPresent(userProfile::setLastName);
        Optional.ofNullable(request.getPhoneNumber()).ifPresent(userProfile::setPhoneNumber);
        Optional.ofNullable(request.getDateOfBirth()).ifPresent(
                dob -> userProfile.setDateOfBirth(Date.from(dob.atStartOfDay(ZoneId.systemDefault()).toInstant())));
        Optional.ofNullable(request.getBio()).ifPresent(userProfile::setBio);
        Optional.ofNullable(request.getGender()).ifPresent(userProfile::setGender);
        Optional.ofNullable(request.getOtherGenderTitle()).ifPresent(userProfile::setGenderOtherTitle);
        userProfile.setUpdatedAt(new Date());
        userProfileRepository.save(userProfile);
        log.info("User profile updated for userId: {}", user.getId());
    }

    /**
     * Delete user profile
     * 
     * @param userId
     * @return void
     * @throws UserProfileNotfoundException if user profile not found
     * @throws Unauthorize                  if trying to delete profile of higher
     *                                      role
     * @throws ProfilePictureException      if error occurs while deleting profile
     *                                      picture
     */
    @Transactional
    public void deleteUserProfile(UUID userId) {
        // Implementation for deleting user profile
        UserEntity user = getUserForOperation(userId);
        UserEntity me = authService.getAuthenticatedUser();
        if (user.getRole().getRank() <= me.getRole().getRank()) {
            throw new Unauthorize("You are not authorized to delete the profile of a user with a higher role.");
        }
        UserProfileEntity userProfile = user.getUserProfile();
        if (userProfile == null) {
            throw new UserProfileNotfoundException("User profile does not exist");
        }
        if (userProfile.getFileId() != null && !userProfile.getFileId().isBlank()) {
            try {
                ImageKit.getInstance().deleteFile(userProfile.getFileId());
                log.info("Deleted profile picture from ImageKit for userId: {}", user.getId());
            } catch (ForbiddenException | TooManyRequestsException | InternalServerException | UnauthorizedException
                    | BadRequestException | UnknownException e) {
                log.error("Error deleting profile picture from ImageKit: {}", e.getMessage());
                throw new ProfilePictureException("Failed to delete profile picture image", e);
            }
        }
        user.setUserProfile(null);
        userRepository.save(user);
        log.info("User profile deleted for userId: {}", user.getId());
    }

    @Transactional
    /**
     * Deletes the profile image of a user from ImageKit and updates the
     * 
     * @param userId the ID of the user whose profile image is to be deleted and
     *               null if self opration
     * @return void
     * @throws Unauthorize                  if the authenticated user is not admin
     *                                      and trying to
     *                                      delete another user's profile image
     * 
     * @throws UserProfileNotfoundException if the user profile does not exist
     * @throws ProfilePictureException      if an error occurs while deleting the
     *                                      profile picture from ImageKit
     * @throws ForbiddenException           if the request is forbidden
     * @throws TooManyRequestsException     if too many requests are made to
     *                                      ImageKit
     * @throws InternalServerException      if an internal server error occurs
     * @throws UnauthorizedException        if the request is unauthorized
     * @throws BadRequestException          if the request is invalid
     * @throws UnknownException             if an unknown error occurs
     */
    public void deleteUserProfileImage(UUID userId) {
        UserEntity user = getUserForOperation(userId);
        UserProfileEntity userProfile = user.getUserProfile();
        if (userProfile == null) {
            throw new UserProfileNotfoundException("User profile does not exist");
        }
        if (userProfile.getFileId() != null && !userProfile.getFileId().isBlank()) {
            try {
                ImageKit.getInstance().deleteFile(userProfile.getFileId());
                log.info("Deleted profile picture from ImageKit for userId: {}", user.getId());
            } catch (ForbiddenException | TooManyRequestsException | InternalServerException | UnauthorizedException
                    | BadRequestException | UnknownException e) {
                log.error("Error deleting profile picture from ImageKit: {}", e.getMessage());
                throw new ProfilePictureException("Failed to delete profile picture image", e);
            }
            userProfile.setFileId(null);
            userProfile.setProfilePictureUrl(null);
            userProfileRepository.save(userProfile);
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
        checkMaxFileSize(file);
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

    /**
     * Retrieves the user entity for the operation based on the provided userId.
     * 
     * @param userId
     * @return {@link UserEntity} userEntity object if another user or authenticated
     *         user
     * @throws Unauthorize                       if the authenticated user is not
     *                                           admin and trying to access other
     *                                           user's data
     * @throws AuthService.UserNotfoundException if the user is not found
     */
    private UserEntity getUserForOperation(UUID userId) {
        UserEntity user;
        if (userId == null) {
            user = authService.getAuthenticatedUser();
        } else {
            UserEntity me = authService.getAuthenticatedUser();
            if (!isAdmin(me)) {
                throw new Unauthorize("Only admin can perform this operation for other users");
            }
            user = userRepository.findById(userId)
                    .orElseThrow(() -> new AuthService.UserNotfoundException("User not found"));
        }
        return user;
    }

    public boolean isAdmin(UserEntity user) {
        return user.getRole().equals(UserRoles.ADMIN) || user.getRole().equals(UserRoles.SUPER_ADMIN);

    }

    public void checkMaxFileSize(MultipartFile file) {
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new InvalidFileException("File size exceeds the maximum limit of 2 MB");
        }
    }

    public static class UserProfileNotfoundException extends RuntimeException {
        public UserProfileNotfoundException(String message) {
            super(message);
        }
    }

    public static class UserProfileAlreadyExistsException extends RuntimeException {
        public UserProfileAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class InvalidFileException extends RuntimeException {
        public InvalidFileException(String message) {
            super(message);
        }
    }

    public static class ProfilePictureException extends RuntimeException {
        public ProfilePictureException(String message) {
            super(message);
        }

        public ProfilePictureException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}