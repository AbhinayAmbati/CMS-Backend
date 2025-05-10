package com.portfolio.cms.Controller;

import com.portfolio.cms.Model.User;
import com.portfolio.cms.Service.AuthService;
import com.portfolio.cms.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthService authService;

    @Autowired
    UserService userService;

    @PostMapping("/signup/initiate")
    public ResponseEntity<Object> initiateSignUp(@RequestBody User user) {
        return authService.initiateSignUp(
                user.getEmail(),
                user.getUsername(),
                user.getPassword()
        );
    }

    @PostMapping("/signup/verify")
    public ResponseEntity<Object> verifyOTPAndCompleteSignUp(@RequestBody VerificationRequest verificationRequest) {
        return authService.verifyOTPAndCompleteSignUp(
                verificationRequest.getEmail(),
                verificationRequest.getOtp()
        );
    }

    @PostMapping("/signup/resend-otp")
    public ResponseEntity<Object> resendOTP(@RequestBody EmailRequest email) {
        return authService.resendOTP(email.getEmail());
    }

    @PostMapping("/signin")
    public ResponseEntity<Object> signIn(@RequestBody User user){
        return authService.signIn(
                user.getEmail(),
                user.getPassword()
        );
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        try {
            String resetToken = userService.createPasswordResetTokenForUser(email);
            authService.sendPasswordResetEmail(email, resetToken);
            return ResponseEntity.ok().body(Map.of("message", "Reset link sent successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "An internal error occurred"));
        }

    }

    @GetMapping("/verify-reset-token/{token}")
    public ResponseEntity<?> verifyResetToken(@PathVariable String token) {

        boolean isValid = userService.validatePasswordResetToken(token);
        if (isValid) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired token"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");

        try {
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok().body(Map.of("message", "Password reset successful"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }
}

class VerificationRequest {
    private String email;
    private String otp;

    // Getters and setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getOtp() { return otp; }
    public void setOtp(String otp) { this.otp = otp; }
}

class EmailRequest {
    private String email;

    // Getters and setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}