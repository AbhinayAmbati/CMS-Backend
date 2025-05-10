package com.portfolio.cms.Service;


import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.portfolio.cms.Dao.AuthDao;
import com.portfolio.cms.Dao.VerificationTokenDao;
import com.portfolio.cms.Model.VerificationToken;
import com.portfolio.cms.config.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.portfolio.cms.Model.User;
import jakarta.servlet.http.HttpServletRequest;

import java.util.*;

import com.portfolio.cms.Dao.PasswordResetDao;
import com.portfolio.cms.Dao.UserDao;
import com.portfolio.cms.Model.PasswordReset;
import jakarta.transaction.Transactional;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Transactional
@Service
public class UserService {

    @Autowired
    UserDao userDao;

    @Autowired
    Cloudinary cloudinary;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private PasswordResetDao passwordResetDao;

    @Autowired
    private AuthDao authDao;

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private VerificationTokenDao verificationTokenDao;
    @Autowired
    JavaMailSender emailSender;

    public String createPasswordResetTokenForUser(String email) {
        User user = userDao.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Delete any existing tokens for this user
        passwordResetDao.deleteByUser(user);

        // Create new token
        String token = UUID.randomUUID().toString();
        PasswordReset resetToken = new PasswordReset();
        resetToken.setUser(user);
        resetToken.setToken(token);
        resetToken.setExpiryDate(LocalDateTime.now().plusMinutes(30));
        passwordResetDao.save(resetToken);

        return token;
    }

    public boolean validatePasswordResetToken(String token) {
        Optional<PasswordReset> resetToken = passwordResetDao.findByToken(token);
        if (resetToken.isEmpty() || resetToken.get().getExpiryDate().isBefore(LocalDateTime.now())) {
            return false;
        }
        return true;
    }

    public void resetPassword(String token, String newPassword) {
        PasswordReset resetToken = passwordResetDao.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token has expired");
        }

        User user = resetToken.getUser();

        if (user == null) {
            throw new RuntimeException("No user associated with this reset token.");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userDao.save(user);
        passwordResetDao.delete(resetToken);
    }

    public ResponseEntity<Object> getUserDetails(HttpServletRequest request) {
        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7); // Remove "Bearer " prefix

            // Validate the token
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract username (email) from token
            String email = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<Object> userData = authDao.findByEmail(email);

            if (userData.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = (User) userData.get();

            // Create response object without sensitive data
            class UserDetailsResponse {
                private Integer id;
                private String username;
                private String email;
                private String profileImage;
                private boolean admin;

                public UserDetailsResponse(User user) {
                    this.id = user.getId();
                    this.username = user.getUsername(); // Assuming username is first name
                    this.email = user.getEmail();
                    this.profileImage = user.getProfileImage();
                    this.admin = user.isAdmin();
                }

                // Getters
                public Integer getId() { return id; }
                public String getUsername() { return username; }
                public String getEmail() { return email; }
                public String getProfileImage() { return profileImage; }
                public boolean isAdmin() { return admin; }
            }

            return ResponseEntity.ok(new UserDetailsResponse(user));
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> updateUserDetails(String username, String email, MultipartFile image, HttpServletRequest request) {
        try {
            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String authenticatedEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userData = userDao.findByEmail(authenticatedEmail);
            if (userData.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userData.get();
            boolean userModified = false;

            // Update username if provided
            if (username != null && !username.isEmpty()) {
                user.setUsername(username);
                userModified = true;
            }

            // Handle email update with security checks
            if (email != null && !email.isEmpty()) {
                if (!authenticatedEmail.equals(email)) {
                    // For email updates, implement additional security
                    // In a real application, you might want to:
                    // 1. Send verification to new email
                    // 2. Require password confirmation
                    // 3. Create a separate endpoint just for email changes
                    return new ResponseEntity<>("Email changes require additional verification",
                            HttpStatus.FORBIDDEN);
                }
                user.setEmail(email);
                userModified = true;
            }

            // Handle image upload if provided
            if (image != null && !image.isEmpty()) {
                String oldImageUrl = user.getProfileImage();

                // Delete old image from Cloudinary if it exists
                if (oldImageUrl != null && !oldImageUrl.isEmpty()) {
                    try {
                        String publicId = oldImageUrl.substring(oldImageUrl.lastIndexOf("/") + 1,
                                oldImageUrl.lastIndexOf("."));
                        cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
                    } catch (Exception e) {
                        return new ResponseEntity<>("Error deleting old image: " + e.getMessage(),
                                HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                }

                try {
                    Map<String, Object> uploadResult = cloudinary.uploader()
                            .upload(image.getBytes(),
                                    Map.of("folder", "user_profiles"));

                    // Get and save the secure URL
                    String newImageUrl = (String) uploadResult.get("secure_url");
                    user.setProfileImage(newImageUrl);
                    userModified = true;
                } catch (Exception e) {
                    return new ResponseEntity<>("Error uploading image: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }

            // Save user if any changes were made
            if (userModified) {
                userDao.save(user);
                return ResponseEntity.ok("User details updated successfully");
            } else {
                return ResponseEntity.ok("No changes made to user details");
            }

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred while updating user details",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> updatePassword(String password, HttpServletRequest request) {
        try {
            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String authenticatedEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userData = userDao.findByEmail(authenticatedEmail);
            if (userData.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userData.get();

            if(passwordEncoder.matches(password, user.getPassword())) {
                return new ResponseEntity<>("New password cannot be same as old password", HttpStatus.BAD_REQUEST);
            }

            // Update password
            user.setPassword(passwordEncoder.encode(password));

            userDao.save(user);

            return ResponseEntity.ok("Password updated successfully");

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred while updating password",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Step 1: Request to change email - initiates OTP verification
    public ResponseEntity<Object> initiateEmailUpdate(String newEmail, HttpServletRequest request) {
        try {
            // Input validation
            if(newEmail == null || newEmail.isEmpty()) {
                return new ResponseEntity<>("New email is required", HttpStatus.BAD_REQUEST);
            }

            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String currentEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userData = userDao.findByEmail(currentEmail);
            if (userData.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userData.get();

            // Check if new email is already registered
            if (userDao.findByEmail(newEmail).isPresent()) {
                return new ResponseEntity<>(newEmail + " is already registered by another user.", HttpStatus.CONFLICT);
            }

            // If new email is same as current email
            if (currentEmail.equals(newEmail)) {
                return new ResponseEntity<>("New email cannot be the same as your current email", HttpStatus.BAD_REQUEST);
            }

            // Generate OTP (6-digit random number)
            String otp = generateOTP();

            // Create or update verification token with special type for email change
            VerificationToken verificationToken = verificationTokenDao
                    .findByEmail(currentEmail)
                    .orElse(new VerificationToken());

            verificationToken.setEmail(currentEmail);
            verificationToken.setToken(otp);
            verificationToken.setExpiryDate(LocalDateTime.now().plusMinutes(10)); // Expires in 10 minutes

            // Store the new email as pendingUserData (reusing field for different purpose)
            verificationToken.setPendingUserData(newEmail);

            verificationTokenDao.save(verificationToken);

            // Send OTP to the NEW email address to verify ownership
            sendEmailChangeOTP(newEmail, otp);

            return new ResponseEntity<>("Verification code sent to " + newEmail, HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred during email update initiation", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000); // Generate a number between 100000 and 999999
        return String.valueOf(otp);
    }

    // Step 2: Verify OTP and complete email change
    public ResponseEntity<Object> verifyOTPAndCompleteEmailUpdate(String otp, HttpServletRequest request) {
        try {
            // Input validation
            if(otp == null || otp.isEmpty()) {
                return new ResponseEntity<>("Verification code is required", HttpStatus.BAD_REQUEST);
            }

            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String currentEmail = jwtUtil.extractUsername(token);

            // Find verification token
            Optional<VerificationToken> optToken = verificationTokenDao.findByEmailAndToken(currentEmail, otp);

            if (optToken.isEmpty()) {
                return new ResponseEntity<>("Invalid verification code", HttpStatus.BAD_REQUEST);
            }

            VerificationToken verificationToken = optToken.get();

            // Check if token is expired
            if (verificationToken.isExpired()) {
                verificationTokenDao.delete(verificationToken);
                return new ResponseEntity<>("Verification code has expired. Please request a new one.", HttpStatus.BAD_REQUEST);
            }

            // Get the new email address
            String newEmail = verificationToken.getPendingUserData();

            // Find the user in the database
            Optional<User> userData = userDao.findByEmail(currentEmail);
            if (userData.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userData.get();

            // Double-check the new email is not taken (in case someone registered between steps)
            if (userDao.findByEmail(newEmail).isPresent()) {
                return new ResponseEntity<>(newEmail + " is already registered by another user.", HttpStatus.CONFLICT);
            }

            // Update the email
            user.setEmail(newEmail);
            userDao.save(user);

            // Clean up verification token
            verificationTokenDao.delete(verificationToken);

            // Generate new JWT token with the new email
            String newToken = jwtUtil.generateToken(newEmail);

            // Create response with new token
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Email updated successfully");
            response.put("token", newToken);

            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred during email update", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Helper method to send OTP for email change
    private void sendEmailChangeOTP(String email, String otp) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Your Email Change Verification Code");
            message.setText("Your verification code to change your account email is: " + otp +
                    "\n\nThis code will expire in 10 minutes. If you didn't request an email change, " +
                    "please ignore this email and secure your account.");

            emailSender.send(message);
        } catch (Exception e) {
            throw e; // Re-throw to be handled by calling method
        }
    }

    public ResponseEntity<Object> deleteAccount(HttpServletRequest request) {
        try {
            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String authenticatedEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userData = userDao.findByEmail(authenticatedEmail);
            if (userData.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userData.get();

            // Delete the user
            userDao.delete(user);

            return ResponseEntity.ok("Account deleted successfully");

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred while deleting account",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}