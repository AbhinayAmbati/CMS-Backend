package com.portfolio.cms.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.portfolio.cms.Dao.AuthDao;
import com.portfolio.cms.Dao.VerificationTokenDao;
import com.portfolio.cms.Model.User;
import com.portfolio.cms.Model.VerificationToken;
import com.portfolio.cms.config.JwtUtil;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;


@Configuration
@Service
public class AuthService {

    @Autowired
    AuthDao authDao;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    JavaMailSender mailSender;
    @Autowired
    private VerificationTokenDao verificationTokenDao;

    @Autowired
    JavaMailSender emailSender;

    public ResponseEntity<Object> initiateSignUp(String email, String username, String password) {
        try {
            // Input validation
            if(email == null || username == null || password == null) {
                return new ResponseEntity<>("Email, username, and password are required", HttpStatus.BAD_REQUEST);
            }

            if (authDao.findByEmail(email).isPresent()) {
                return new ResponseEntity<>(email + " is already registered.", HttpStatus.CONFLICT);
            }

            // Password strength validation (optional)
            if (password.length() < 6) {
                return new ResponseEntity<>("Password must be at least 6 characters long", HttpStatus.BAD_REQUEST);
            }

            // Generate OTP (6-digit random number)
            String otp = generateOTP();

            // Hash the password for security
            String hashedPassword = encoder.encode(password);

            // Create a temporary user object with pending status
            User pendingUser = new User();
            pendingUser.setEmail(email);
            pendingUser.setUsername(username);
            pendingUser.setPassword(hashedPassword);
            pendingUser.setVerified(false); // Not verified yet

            // Convert pending user to JSON
            ObjectMapper objectMapper = new ObjectMapper();
            String pendingUserJson = objectMapper.writeValueAsString(pendingUser);

            // Create or update verification token
            VerificationToken verificationToken = verificationTokenDao
                    .findByEmail(email)
                    .orElse(new VerificationToken());

            verificationToken.setEmail(email);
            verificationToken.setToken(otp);
            verificationToken.setExpiryDate(LocalDateTime.now().plusMinutes(10)); // Expires in 10 minutes
            verificationToken.setPendingUserData(pendingUserJson);

            verificationTokenDao.save(verificationToken);

            // Send OTP to user's email
            sendOTPEmail(email, otp);

            return new ResponseEntity<>("Verification code sent to " + email, HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred during signup initiation", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // User registration step 2: Verify OTP and complete registration
    public ResponseEntity<Object> verifyOTPAndCompleteSignUp(String email, String otp) {
        try {
            // Input validation
            if(email == null || otp == null) {
                return new ResponseEntity<>("Email and OTP are required", HttpStatus.BAD_REQUEST);
            }

            // Find verification token
            Optional<VerificationToken> optToken = verificationTokenDao.findByEmailAndToken(email, otp);

            if (optToken.isEmpty()) {
                return new ResponseEntity<>("Invalid verification code", HttpStatus.BAD_REQUEST);
            }

            VerificationToken verificationToken = optToken.get();

            // Check if token is expired
            if (verificationToken.isExpired()) {
                verificationTokenDao.delete(verificationToken);
                return new ResponseEntity<>("Verification code has expired. Please request a new one.", HttpStatus.BAD_REQUEST);
            }

            // Convert JSON back to User object
            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(verificationToken.getPendingUserData(), User.class);
            user.setVerified(true); // Mark as verified

            // Save the verified user to the database
            authDao.save(user);

            // Clean up verification token
            verificationTokenDao.delete(verificationToken);

            // Optional: Generate JWT token for immediate login
            String token = jwtUtil.generateToken(user.getEmail());

            // Create response with token
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Registration successful");
            response.put("token", token);
            response.put("user", user);

            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred during signup completion", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Helper method to generate a 6-digit OTP
    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000); // Generate a number between 100000 and 999999
        return String.valueOf(otp);
    }

    // Helper method to send OTP via email
    private void sendOTPEmail(String email, String otp) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject("Your Registration Verification Code");
            message.setText("Your verification code is: " + otp +
                    "\n\nThis code will expire in 10 minutes. If you didn't request this code, please ignore this email.");

            emailSender.send(message);
        } catch (Exception e) {
            throw e; // Re-throw to be handled by calling method
        }
    }

    public ResponseEntity<Object> resendOTP(String email) {
        try {
            // Input validation
            if (email == null || email.isEmpty()) {
                return new ResponseEntity<>("Email is required", HttpStatus.BAD_REQUEST);
            }

            // Check if email exists in our verification system
            Optional<VerificationToken> optToken = verificationTokenDao.findByEmail(email);

            if (optToken.isEmpty()) {
                return new ResponseEntity<>("No pending registration found for this email", HttpStatus.BAD_REQUEST);
            }

            VerificationToken verificationToken = optToken.get();

            // Generate new OTP
            String newOtp = generateOTP();

            // Update token and expiry
            verificationToken.setToken(newOtp);
            verificationToken.setExpiryDate(LocalDateTime.now().plusMinutes(10)); // Reset expiry to 10 minutes

            verificationTokenDao.save(verificationToken);

            // Send the new OTP
            sendOTPEmail(email, newOtp);

            return new ResponseEntity<>("New verification code sent to " + email, HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity<>("An error occurred while resending verification code",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



    public ResponseEntity<Object> signIn(String email, String password) {
        try {
            Optional<Object> userData = authDao.findByEmail(email);
            if (userData.isEmpty()) {
                return new ResponseEntity<>(email + " is not registered.", HttpStatus.NOT_FOUND);
            }

            User user = (User) userData.get();

            if (!encoder.matches(password, user.getPassword())) {
                return new ResponseEntity<>("Incorrect Password", HttpStatus.UNAUTHORIZED);
            }

            // Create authorities list based on admin flag
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // All users get USER role

            // Add ADMIN role if user is an admin
            if (user.isAdmin()) {
                authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }

            // Create UserDetails object
            UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                    user.getEmail(),
                    user.getPassword(),
                    authorities
            );

            // Generate JWT with authorities included
            String jwtToken = jwtUtil.generateToken(userDetails);

            // Response wrapper class
            class JwtResponse {
                private String jwtToken;
                private User user;
                private boolean isAdmin;

                public JwtResponse(String jwtToken, User user, boolean isAdmin) {
                    this.jwtToken = jwtToken;
                    this.user = user;
                    this.isAdmin = isAdmin;
                }

                public String getJwtToken() {
                    return jwtToken;
                }

                public void setJwtToken(String jwtToken) {
                    this.jwtToken = jwtToken;
                }

                public User getUser() {
                    return user;
                }

                public void setUser(User user) {
                    this.user = user;
                }

                public boolean isAdmin() {
                    return isAdmin;
                }

                public void setAdmin(boolean admin) {
                    isAdmin = admin;
                }
            }

            JwtResponse jwtResponse = new JwtResponse(jwtToken, user, user.isAdmin());
            return ResponseEntity.ok(jwtResponse);

        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public void sendPasswordResetEmail(String email, String token) {
        String resetUrl = "http://localhost:5173" + "/reset-password/" + token;
        String subject = "Password Reset Request";
        String content = String.format("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                line-height: 1.7;
                color: #2d3748;
                margin: 0;
                padding: 0;
                background-color: #f7fafc;
            }
            .container {
                max-width: 600px;
                margin: 40px auto;
                padding: 0;
                background-color: #ffffff;
                border-radius: 12px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .header {
                background: linear-gradient(135deg, #4299e1 0%%, #3182ce 100%%);
                padding: 32px 20px;
                text-align: center;
                border-radius: 12px 12px 0 0;
            }
            .header h1 {
                color: #ffffff;
                margin: 0;
                font-size: 28px;
                font-weight: 600;
                letter-spacing: 0.5px;
            }
            .content {
                padding: 40px 32px;
                background-color: #ffffff;
                border-radius: 0 0 12px 12px;
            }
            .button {
                display: inline-block;
                padding: 14px 32px;
                background: linear-gradient(135deg, #4299e1 0%%, #3182ce 100%%);
                color: #ffffff;
                text-decoration: none;
                border-radius: 8px;
                margin: 24px 0;
                font-weight: 600;
                letter-spacing: 0.5px;
                transition: transform 0.2s ease, box-shadow 0.2s ease;
                box-shadow: 0 2px 4px rgba(66, 153, 225, 0.3);
            }
            .button:hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(66, 153, 225, 0.4);
            }
            .note {
                font-size: 14px;
                color: #718096;
                margin-top: 24px;
                padding: 16px;
                background-color: #f8fafc;
                border-radius: 8px;
                border-left: 4px solid #4299e1;
            }
            .footer {
                text-align: center;
                margin-top: 32px;
                padding-top: 24px;
                border-top: 1px solid #e2e8f0;
                font-size: 13px;
                color: #718096;
            }
            p {
                margin: 16px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Reset Request</h1>
            </div>
            <div class="content">
                <p>Hello,</p>
                <p>We received a request to reset your password. To create a new password, please click the secure button below:</p>
                <div style="text-align: center;">
                    <a href="%s" class="button">Reset Password</a>
                </div>
                <div class="note">
                    <strong>Security Notice:</strong>
                    <p style="margin: 8px 0 0 0">• This link will expire in 30 minutes</p>
                    <p style="margin: 4px 0 0 0">• If you didn't request this reset, please ignore this email</p>
                    <p style="margin: 4px 0 0 0">• Contact our support team if you have any concerns</p>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p style="margin-top: 8px;">© 2025 Job Portal. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
""", resetUrl);

        // Create MimeMessage instead of SimpleMailMessage to support HTML
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "UTF-8");

        try {
            helper.setTo(email);
            helper.setSubject(subject);
            helper.setText(content, true); // Set second parameter to true for HTML
            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }

}
