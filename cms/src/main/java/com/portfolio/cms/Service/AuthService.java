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
        String subject = "Your Registration Verification Code";
        String content = String.format("""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Code</title>
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
                background: linear-gradient(135deg, #38b2ac 0%%, #319795 100%%);
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
            .otp-container {
                margin: 24px 0;
                text-align: center;
            }
            .otp-code {
                display: inline-block;
                padding: 16px 32px;
                background-color: #edf2f7;
                border-radius: 8px;
                font-size: 32px;
                font-weight: 700;
                letter-spacing: 4px;
                color: #2d3748;
                border: 1px dashed #cbd5e0;
            }
            .note {
                font-size: 14px;
                color: #718096;
                margin-top: 24px;
                padding: 16px;
                background-color: #f8fafc;
                border-radius: 8px;
                border-left: 4px solid #38b2ac;
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
                <h1>Verification Code</h1>
            </div>
            <div class="content">
                <p>Hello,</p>
                <p>Thank you for registering with us. To complete your registration, please use the verification code below:</p>
                <div class="otp-container">
                    <div class="otp-code">%s</div>
                </div>
                <div class="note">
                    <strong>Important Information:</strong>
                    <p style="margin: 8px 0 0 0">• This code will expire in 10 minutes</p>
                    <p style="margin: 4px 0 0 0">• If you didn't request this code, please ignore this email</p>
                    <p style="margin: 4px 0 0 0">• Do not share this code with anyone</p>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p style="margin-top: 8px;">© 2025 Job Portal. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """, otp);

        try {
            // Create MimeMessage instead of SimpleMailMessage to support HTML
            MimeMessage mimeMessage = emailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "UTF-8");

            helper.setTo(email);
            helper.setSubject(subject);
            helper.setText(content, true); // Set second parameter to true for HTML
            emailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send OTP verification email", e);
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

            // Create response with only the requested fields
            Map<String, Object> response = new HashMap<>();
            response.put("jwtToken", jwtToken);
            response.put("isAdmin", user.isAdmin());

            // Create a simplified user object with only the requested fields
            Map<String, Object> simplifiedUser = new HashMap<>();
            simplifiedUser.put("id", user.getId());
            simplifiedUser.put("username", user.getUsername());
            simplifiedUser.put("email", user.getEmail());
            simplifiedUser.put("password", user.getPassword());
            simplifiedUser.put("admin", user.isAdmin());
            simplifiedUser.put("profileImage", user.getProfileImage());
            simplifiedUser.put("verified", user.isVerified());

            response.put("user", simplifiedUser);

            return ResponseEntity.ok(response);

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
    <title>Password Reset - Content Management System</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.7;
            color: #333333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 600px;
            margin: 40px auto;
            padding: 0;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%%, #1a202c 100%%);
            padding: 28px 20px;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }
        .header h1 {
            color: #ffffff;
            margin: 0;
            font-size: 26px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .content {
            padding: 36px 32px;
            background-color: #ffffff;
            border-radius: 0 0 8px 8px;
        }
        .button {
            display: inline-block;
            padding: 12px 30px;
            background: linear-gradient(135deg, #2c3e50 0%%, #1a202c 100%%);
            color: #ffffff;
            text-decoration: none;
            border-radius: 6px;
            margin: 24px 0;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.2s ease;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
        }
        .button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        .note {
            font-size: 14px;
            color: #555555;
            margin-top: 24px;
            padding: 16px;
            background-color: #f8f9fa;
            border-radius: 6px;
            border-left: 4px solid #2c3e50;
        }
        .footer {
            text-align: center;
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #e9ecef;
            font-size: 13px;
            color: #6c757d;
        }
        p {
            margin: 16px 0;
            color: #444444;
        }
        .logo {
            margin-bottom: 15px;
            font-size: 20px;
            font-weight: bold;
            color: #ffffff;
            letter-spacing: 1px;
        }
        .accent {
            color: #2c3e50;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">CONTENT MANAGEMENT SYSTEM</div>
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>We received a request to reset your password for your <span class="accent">Content Management System</span> account. To create a new password, please click the secure button below:</p>
            <div style="text-align: center;">
                <a href="%s" class="button">Reset Password</a>
            </div>
            <div class="note">
                <strong>Security Notice:</strong>
                <p style="margin: 8px 0 0 0">• This link will expire in 30 minutes</p>
                <p style="margin: 4px 0 0 0">• If you didn't request this reset, please ignore this email</p>
                <p style="margin: 4px 0 0 0">• Contact our support team if you have any concerns</p>
            </div>
            <p style="margin-top: 24px; font-size: 15px;">Once you've reset your password, you'll be able to access all your content and management tools again.</p>
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply to this email.</p>
            <p style="margin-top: 8px;">© 2025 Content Management System. All rights reserved.</p>
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
