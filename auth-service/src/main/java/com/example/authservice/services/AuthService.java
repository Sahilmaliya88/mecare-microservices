package com.example.authservice.services;
import com.example.authservice.DTOS.*;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.repositories.UserRepository;
import com.example.authservice.utils.LoginProviders;
import com.example.authservice.utils.UserRoles;
import com.example.authservice.utils.exceptions.Unauthorize;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.User;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;

import org.springframework.http.*;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;


@Slf4j
@Service
public class AuthService {
    private static final String NUMBERS = "0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int OTP_LENGTH = 6;
    private static final int OTP_EXPIRY_MINUTES = 15;
    private static final String USER_EMAIL_HEADER = "x-user-email";
    private static final String VERSION_PREFIX = "version-";
    private static final String IMPERSONATE_PREFIX = "impersonate-";
    private static final String IMPERSONATE_BY = "x-user-impersonate_by";
    private static final String IMPERSONATE = "x-user-impersonate";
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final JWTService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String,Object> redisTemplate;
    private final AuthenticationManager authenticationManager;
    private final RestTemplate restTemplate;
    public AuthService(UserRepository userRepository, EmailService emailService, JWTService jwtService, PasswordEncoder passwordEncoder, RedisTemplate<String,Object> redisTemplate, AuthenticationManager authenticationManager, RestTemplate restTemplate){
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.redisTemplate = redisTemplate;
        this.authenticationManager = authenticationManager;
        this.restTemplate = restTemplate;
    }
    public String registerUser(RegisterUserRequest registerUserRequest) throws JsonProcessingException {
        //create hash of password
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
        String hashedPassword = passwordEncoder.encode(registerUserRequest.getPassword());
        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        String otp = generateOtp(6);
        Date verificationCodeExpiresAt = new Date(new Date().getTime()+15*60*1000);
        //create user
        UserEntity newUser =UserEntity.builder()
                .email(registerUserRequest.getEmail())
                .password(hashedPassword)
                .token_version(tokenVersion)
                .created_at(new Date())
                .verification_code_expires_at(verificationCodeExpiresAt)
                .verification_code(otp)
                .build();
        //send verification code
        userRepository.save(newUser);
        //generate token and set version to redis
        redisTemplate.opsForValue().set(VERSION_PREFIX+newUser.getEmail(),newUser.getToken_version());
        String jwtToken = generateJwt(newUser);
        //save user
        emailService.sendWelcomeEmail(newUser);
        //return response
        return jwtToken;
    }
    public String verifyUser(VerifyRequest verifyRequest) throws JsonProcessingException {
        UserEntity userEntity = userRepository.findByEmail(verifyRequest.getEmail())
                .orElseThrow(()->new Unauthorize("User not found with this email"));
        if(!Objects.equals(userEntity.getVerification_code(), verifyRequest.getOtp())) throw new Unauthorize("Invalid Otp", HttpStatus.UNAUTHORIZED);
        if(userEntity.getVerification_code_expires_at().before(new Date())) throw new Unauthorize("Otp expired!.please request new one",HttpStatus.BAD_REQUEST);
        userEntity.setIs_verified(true);
        userEntity.setVerification_code(null);
        userEntity.setVerification_code_expires_at(null);
        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        redisTemplate.opsForValue().set(VERSION_PREFIX+userEntity.getEmail(),tokenVersion);
        userEntity.setToken_version(tokenVersion);
        userRepository.save(userEntity);
        return jwtService.getJwtToken(userEntity);
    }
    public String loginUser(RegisterUserRequest registerUserRequest) throws JsonProcessingException {
         Authentication authentication= authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(registerUserRequest.getEmail(),registerUserRequest.getPassword()));
         if(!authentication.isAuthenticated()) throw new Unauthorize("Invalid credentials!");
         UserEntity userEntity = userRepository.findByEmail(registerUserRequest.getEmail())
                 .orElseThrow(()->new Unauthorize("User not found!"));
         if(userEntity.getProvider() != LoginProviders.EMAIL){
             throw new InvalidLoginTypeException("Please login through "+userEntity.getProvider());
         }
         String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
         userEntity.setToken_version(tokenVersion);
         userRepository.save(userEntity);
         redisTemplate.opsForValue().set(VERSION_PREFIX+userEntity.getEmail(),tokenVersion);
         return generateJwt(userEntity);
    }
    /**
     * Retrieves the authenticated user's details from the security context.
     *
     * @return the {@link UserEntity} associated with the authenticated user's email
     * @throws Unauthorize if the user is not authenticated or the email is invalid
     */
    public UserEntity getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || authentication.getPrincipal() instanceof AnonymousAuthenticationToken) {
            throw new Unauthorize("User must be logged in to access this resource");
        }

        String email = authentication.getName();
        log.info("is authenticated {}", authentication.isAuthenticated());
        if (email == null || email.isBlank()) {
            throw new Unauthorize("Invalid authentication details: email not found");
        }
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new Unauthorize("No user found with email: " + email));
    }
    /**
     * Send verification code if user is not verified
     * throws Unauthorize if the user is not authenticated or the email is invalid also can throw mail error
     */
    public void  sendVerificationCode(){
        UserEntity user = getAuthenticatedUser();
        // Generate OTP and set expiration
        if(user.getIs_verified()){
            throw new AlreadyVerifiedException("User is already verified");
        }
        String verificationCode = generateOtp(OTP_LENGTH);
        Instant expiryTime = Instant.now().plus(OTP_EXPIRY_MINUTES, ChronoUnit.MINUTES);
        // Update user entity
        user.setVerification_code(verificationCode);
        user.setVerification_code_expires_at(Date.from(expiryTime));
        try {
            userRepository.save(user);
            log.info("Saved verification code for user {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to save user {}: {}", user.getEmail(), e.getMessage(), e);
            throw new RuntimeException("Failed to persist verification code", e);
        }

        // Send verification email
        try {
            emailService.sendVerificationCodeEmail(user);
            log.info("Verification code sent to {}", user.getEmail());
        } catch (EmailService.EmailSendingException e) {
            log.error("Failed to send verification email to {}: {}", user.getEmail(), e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Generates Uniques password reset link valid for 15 minutes and sends user through mail
     * @param email  the user's email
     * @throws UserNotfoundException throws this exception if user not found with provided email
     *
     */
    public void sendPasswordResetLink(String email){
        UserEntity userEntity = userRepository.findByEmail(email)
                .orElseThrow(()->new UserNotfoundException("User not found with email: "+email));
        //generate a string
        if(userEntity.getProvider() != LoginProviders.EMAIL){
            throw new InvalidLoginTypeException("You can not change password!");
        }
        String passwordResetToken = generateRandomToken(32);
        Instant instant = Instant.now().plus(15,ChronoUnit.MINUTES);
        //generated token and expiry data into user entity object
        userEntity.setPassword_reset_token(passwordResetToken);
        userEntity.setPassword_reset_token_expires_at(Date.from(instant));
        //send verification code
        emailService.sendPasswordResetLink(userEntity);
        userRepository.save(userEntity);
    }

    /**
     * verifies password reset token and if finds valid then changes password
     * @param token   password reset-token received from user
     * @param resetPasswordRequest request body {@link ResetPasswordRequest}
     * @throws InvalidTokenException if token is invalid or expired
     * @throws IllegalArgumentException if body is empty
     * @throws RuntimeException if failed to save in database
     */
    public void changePassword(String token, ResetPasswordRequest resetPasswordRequest){
        UserEntity user = userRepository.findByValidPasswordResetToken(token,new Date())
                .orElseThrow(()-> new InvalidTokenException("Token is Invalid or expired!"));
        if(resetPasswordRequest.getPassword() == null){
            throw new IllegalArgumentException("Please provide password to change");
        }
        if(user.getProvider() != LoginProviders.EMAIL){
            throw new InvalidLoginTypeException("You can not change password cause you registered with "+user.getProvider());
        }
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        user.setPassword(encoder.encode(resetPasswordRequest.getPassword()));
        user.setPassword_reset_token_expires_at(null);
        user.setPassword_reset_token(null);
        user.setToken_version(null);
        user.setUpdated_at(new Date());
        //remove version from redis
        redisTemplate.opsForValue().getAndDelete(VERSION_PREFIX+user.getEmail());
        try {
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * calls login functions of required oauth provides
     * @param socialLoginRequestBody {@link SocialLoginRequest} an request object received from user
     * @return {@link String} jwt token generated for that user
     */
    public String socialLogin(SocialLoginRequest socialLoginRequestBody){
        if (Objects.requireNonNull(socialLoginRequestBody.getProvider()) == LoginProviders.GOOGLE) {
         return googleOauthLogin(socialLoginRequestBody.getAccessToken());
        } else {
            throw new InvalidLoginTypeException("Current provider is not available");
        }
    }

    /**
     * fetches user profile from Google using access token
     * register user if not exists or returns jwt token if user exists
     * @param accessToken {@link String} access token for Google apis
     * @throws InvalidLoginTypeException if user tries to log in with different provider than registered
     * @throws IllegalArgumentException if access token is missing
     * @throws RestClientException if retrieves invalid response from Google
     * @throws RuntimeException if failed to save user into database
     */
    private String googleOauthLogin(String accessToken){
        if(accessToken.isBlank()){
            log.error("access token is missing");
            throw new IllegalArgumentException("access token is required");
        }
        try{
            String googleProfileApiUrl = "https://www.googleapis.com/oauth2/v2/userinfo";
            //prepare request entity
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> httpEntity = new HttpEntity<>(httpHeaders);
            log.info("making google user profile request with {}",googleProfileApiUrl);
            //sends request to google for profile details
            ResponseEntity<GoogleUserProfileResponse> googleProfileResponse= restTemplate
                    .exchange(googleProfileApiUrl, HttpMethod.GET,httpEntity, GoogleUserProfileResponse.class);
            //throws error if response is invalid
            if(googleProfileResponse.getStatusCode() != HttpStatus.OK || googleProfileResponse.getBody() == null){
                log.error("failed to retrieve user profile from google: {}",googleProfileResponse.getStatusCode());
                throw new RestClientException("Invalid response from Google API");
            }
            GoogleUserProfileResponse googleProfile = googleProfileResponse.getBody();
            log.info("successfully user profile retrieved of: {}",googleProfile.getFamily_name());
            //check user exists
            if(googleProfile.getEmail() == null || googleProfile.getEmail().isBlank()){
                throw new IllegalArgumentException("Email is missing from google response");
            }
            Optional<UserEntity> optionalUser = userRepository.findByEmail(googleProfile.getEmail());
            if(optionalUser.isPresent()){
                UserEntity user = optionalUser.get();
                log.info("optional user from database {}",user.getEmail());
                //throws error if provider is different
                if(user.getProvider() != LoginProviders.GOOGLE){
                    throw new InvalidLoginTypeException("Please login with "+user.getProvider());
                }
                //generate token version
                String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
                user.setToken_version(tokenVersion);
                //save user
                try{
                    userRepository.save(user);
                } catch (RuntimeException e) {
                    log.error("failed to save user");
                    throw new RuntimeException(e);
                }
                redisTemplate.opsForValue().set(VERSION_PREFIX+user.getEmail(),tokenVersion);
                //generate jwt and save user
                return generateJwt(user);
            }else {
                String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
                UserEntity user = UserEntity.builder()
                        .email(googleProfile.getEmail())
                        .provider(LoginProviders.GOOGLE)
                        .is_verified(true)
                        .providerId(googleProfile.getId())
                        .password(googleProfile.getId())
                        .role(UserRoles.USER)
                        .token_version(tokenVersion)
                        .build();
                try{
                    userRepository.save(user);
                } catch (RuntimeException e) {
                    log.error("failed to save user");
                    throw new RuntimeException(e);
                }
                redisTemplate.opsForValue().set(VERSION_PREFIX+user.getEmail(),tokenVersion);
                return generateJwt(user);
            }
        }catch (RestClientException e){
            log.error("unexpected error encountered during request: {}",e.getMessage());
            throw e;
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * Changes user roles
     * @param changeUserRoleRequest the request body {@link ChangeUserRoleRequest}
     */
    public void changeUserRole(ChangeUserRoleRequest changeUserRoleRequest){
        UserEntity operator = getAuthenticatedUser();
        if(operator == null){
            throw new Unauthorize("Please login!");
        }
        if(operator.getEmail().equals(changeUserRoleRequest.getEmail())){
            throw new SameUserException("You can not change own role");
        }
        log.info("operator rank is {}",operator.getRole().getRank());
        try {
            if(operator.getRole() == null || operator.getRole().equals(UserRoles.USER) || operator.getRole().equals(UserRoles.DOCTOR)){
                throw new Unauthorize("You don't have permission to perform this action");
            }
            //fetch user
            UserEntity user = userRepository.findByEmail(changeUserRoleRequest.getEmail())
                    .orElseThrow(()->new UserNotfoundException("User not found with this email"));
            boolean isPermitted = checkUserCanChangeRole(operator.getRole(),user.getRole(),changeUserRoleRequest.getUserRole());
            if(!isPermitted){
                throw new Unauthorize("you are unauthorized to perform this action");
            }
            user.setRole(changeUserRoleRequest.getUserRole());
            user.setUpdated_at(new Date());
            try {
                userRepository.save(user);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            String USER_VERSION_KEY = "version-"+user.getEmail();
            String redisTokenVersion = (String) redisTemplate.opsForValue().get(USER_VERSION_KEY);
            if(redisTokenVersion == null || redisTokenVersion.isBlank()){
                return;
            }
            int dashIndex = redisTokenVersion.indexOf("-");
            String updatedTokenForUser;
            if(dashIndex !=1 && dashIndex == redisTokenVersion.length()-2){
                updatedTokenForUser = redisTokenVersion.substring(0,dashIndex)+"-"+user.getRole().getRank();
            }else{
                updatedTokenForUser = redisTokenVersion+"-"+user.getRole().getRank();
            }
            try {
                redisTemplate.opsForValue().set(USER_VERSION_KEY,updatedTokenForUser);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Process the CSV files from the request and Insert to the database
     * @param request {@link UploadCsvRequest} object containing CSV file
     * @return {@link Integer} total number of inserted records
     * @throws IllegalArgumentException if file is invalid of empty
     * @throws RuntimeException if database operation fails
     */
    public int insertUsers(UploadCsvRequest request){
        MultipartFile file = request.getFile();
        if(file == null || file.isEmpty()){
            throw new IllegalArgumentException("Please enter valid file");
        }
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8));
            CSVFormat csvFormat = CSVFormat.
                    DEFAULT
                    .builder()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .setIgnoreHeaderCase(true)
                    .setTrim(true)
                    .build();
            CSVParser csvRecord = csvFormat.parse(reader);
            List<UserEntity> users = csvRecord.stream()
                    .filter(record -> record.get("email") != null || !record.get("email").isEmpty())
                    .map(this::insertUser)
                    .toList();
            try {
                userRepository.saveAll(users);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return users.size();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public String impersonateUser(String email) throws JsonProcessingException {
        if(email == null || email.isEmpty()){
            throw new IllegalArgumentException("Invalid parameters");
        }
        UserEntity performer = this.getAuthenticatedUser();
        if(performer == null){
            throw new Unauthorize("Please login before perform this action");
        }
        if(performer.getRole() != UserRoles.ADMIN && performer.getRole() != UserRoles.SUPER_ADMIN){
            throw new Unauthorize("You can not impersonate any user");
        }
        UserEntity targetUser = userRepository.findByEmail(email)
                .orElseThrow(()-> new UserNotfoundException("User not found with email:"+email));
        if(targetUser.getRole().getRank() < performer.getRole().getRank()){
            throw new Unauthorize("You can not impersonate your superior");
        }
        long tokenVersion = ThreadLocalRandom.current().nextLong();
        String updatedToken = jwtService.getJwtToken(targetUser,performer.getEmail(),Long.toString(tokenVersion));
        ListOperations<String,Object> listOps = redisTemplate.opsForList();
        String Key = IMPERSONATE_PREFIX+targetUser.getEmail();
        listOps.rightPush(Key,tokenVersion);
        return updatedToken;
    }
    /**
     * converts valid csv record to UserEntity
     * @param record {@link CSVRecord} a record containing email and password
     * @return {@link UserEntity} an userEntity
     */
    private UserEntity insertUser(CSVRecord record){
        String email = record.get("email");
        String password = record.get("password");
        if(email == null || email.isBlank()){
            return null;
        }
       String decodedPassword = passwordEncoder.encode(password);
        return UserEntity.builder()
                .email(email)
                .password(decodedPassword)
                .is_verified(true)
                .created_at(new Date())
                .isActive(true)
                .provider(LoginProviders.EMAIL)
                .build();
    }
    /**
     * Function end impersonating session retrieved from token and headers
     * @param request {@link HttpServletRequest} request object
     * @throws InvalidTokenException if token have invalid version number or missing any data
     * @throws RuntimeException if any headers are missing
     * @throws UserNotfoundException if actual user not present in database
     * @throws JsonProcessingException if any failed to create or parse jwt token
     */
    public String exitImpersonating(HttpServletRequest request) throws JsonProcessingException {
        String token = extractAuthorizationToken(request);
        if (!isValidRequestForExitImpersonate(request)) {
            throw new RuntimeException("Not currently impersonating");
        }

        Map<String, Object> claims = jwtService.getJwtClaims(token);
        String versionStr = (String) claims.get("version");
        if (versionStr == null) {
            throw new InvalidTokenException("Invalid or missing version in token");
        }

        long version;
        try {
            version = Long.parseLong(versionStr);
        } catch (NumberFormatException e) {
            throw new InvalidTokenException("Invalid version format in token");
        }

        String redisKey = IMPERSONATE_PREFIX + request.getHeader(USER_EMAIL_HEADER);
        List<Object> versions = redisTemplate.opsForList().range(redisKey, 0, -1);
        if (versions == null || versions.isEmpty() || !versions.contains(version)) {
            throw new InvalidTokenException("Invalid token version");
        }
        log.info("Versions {}",versions.toString());
        redisTemplate.opsForList().remove(redisKey, 1, version);

        String actualUserEmail = request.getHeader(IMPERSONATE_BY);
        UserEntity user = userRepository.findByEmail(actualUserEmail)
                .orElseThrow(() -> new UserNotfoundException("User not found: " + actualUserEmail));

        long newTokenVersion = ThreadLocalRandom.current().nextLong();
        redisTemplate.opsForValue().set(VERSION_PREFIX + user.getEmail(), newTokenVersion);
        user.setToken_version(Long.toString(newTokenVersion));
        userRepository.save(user);

        return jwtService.getJwtToken(user);
    }
    /**
     * Validates if the request is eligible for exiting impersonation.
     *
     * @param request The HTTP request object.
     * @return True if the request is valid for exiting impersonation, false otherwise.
     */
    private boolean isValidRequestForExitImpersonate(HttpServletRequest request) {
        String email = request.getHeader(IMPERSONATE_BY);
        String impersonatingHeader = request.getHeader(IMPERSONATE);
        return email != null && !email.isEmpty() &&
                "true".equalsIgnoreCase(impersonatingHeader);
    }

    /**
     * Extracts the JWT token from the Authorization header.
     *
     * @param request The HTTP request object.
     * @return The extracted JWT token.
     * @throws Unauthorize If the Authorization header is missing or invalid.
     */
    private String extractAuthorizationToken(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String BEARER_PREFIX = "Bearer ";
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            throw new Unauthorize("Invalid or missing Authorization header");
        }
        return authHeader.substring(BEARER_PREFIX.length());
    }
    /**
     * Check role hierarchy that is performer is superior to target role and current user role
     * @param performerRole - {@link UserRoles} role of Action performer
     * @param currentUserRole - {@link UserRoles} current role user
     * @param targetRole - {@link UserRoles} target role
     * @return true if performer is superior else false
     * @throws IllegalArgumentException if any function parameters are invalid
     */
    public boolean checkUserCanChangeRole(UserRoles performerRole,UserRoles currentUserRole,UserRoles targetRole){
        if(performerRole == null || currentUserRole == null || targetRole == null){
            throw new IllegalArgumentException("Invalid parameter to perform this action");
        }
        int indexOfPerformerRole = performerRole.getRank();
        int indexOfUserRole = currentUserRole.getRank();
        int indexOfRoleToChange = targetRole.getRank();
        if(indexOfPerformerRole < 0 || indexOfUserRole < 0  || indexOfRoleToChange < 0){
            throw new IllegalArgumentException("Invalid roles!");
        }
        return indexOfPerformerRole <= indexOfUserRole && indexOfPerformerRole <= indexOfRoleToChange;
    }
    /**
     * Generates a random token as a Base64-encoded string.
     *
     * @param length the number of random bytes to generate (must be positive)
     * @return a Base64-URL-encoded string representing the random bytes
     * @throws IllegalArgumentException if length is less than 1
     */
    public static String generateRandomToken(int length) {
        if (length < 1) {
            throw new IllegalArgumentException("Token length must be at least 1");
        }
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private String generateJwt(UserEntity userEntity) throws JsonProcessingException {
        return jwtService.getJwtToken(userEntity);
    }
    private String generateOtp(int size) {
        SecureRandom random = new SecureRandom();
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }
    /**
    * A custom exception to user if already verified and sends verification code request
    * */
    public static class AlreadyVerifiedException extends RuntimeException {
        public AlreadyVerifiedException(String message){
            super(message);
        }
    }
    /**
     * A custom exception if User not found with provided details
     * */
    public static class UserNotfoundException extends RuntimeException{
        public UserNotfoundException(String message){
            super(message);
        }
    }
    /**
     * A custom exception if password reset token is invalid
     */
    public static class InvalidTokenException extends RuntimeException{
        public InvalidTokenException(String message){
            super(message);
        }
    }

    /**
     * A custom exception if user try to log in with different provider than registered
     */
    public static class InvalidLoginTypeException extends RuntimeException{
        public InvalidLoginTypeException(String message){
            super(message);
        }
    }
    public static class SameUserException extends RuntimeException{
        public SameUserException(String message){
            super(message);
        }
    }
}
