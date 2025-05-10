package com.portfolio.cms.Controller;


import com.portfolio.cms.Model.User;
import com.portfolio.cms.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    UserService userService;

    @GetMapping("/getuserdetails")
    public ResponseEntity<Object> getUserDetails(HttpServletRequest request) {
        return userService.getUserDetails(
                request
        );
    }

    @PostMapping("/updateuser")
    public ResponseEntity<Object> updateUserDetails(
            @RequestPart("user") User user,
            @RequestPart(value = "image", required = false) MultipartFile image,
            HttpServletRequest request) {
        return userService.updateUserDetails(
                user.getUsername(),
                user.getEmail(),
                image,
                request
        );
    }

    @PostMapping("/email/update/initiate")
    public ResponseEntity<Object> initiateEmailUpdate(@RequestBody EmailRequest emailRequest, HttpServletRequest request) {
        return userService.initiateEmailUpdate(
                emailRequest.getEmail(),
                request
        );
    }

    @PostMapping("/email/update/verify")
    public ResponseEntity<Object> verifyOTPAndCompleteEmailUpdate(@RequestBody OtpRequest otpRequest, HttpServletRequest request) {
        return userService.verifyOTPAndCompleteEmailUpdate(
                otpRequest.getOtp(),
                request
        );
    }

    @PostMapping("/updatepassword")
    public ResponseEntity<Object> updatePassword(@RequestBody User user, HttpServletRequest request) {
        return userService.updatePassword(
                user.getPassword(),
                request
        );
    }

    @DeleteMapping("/deleteaccount")
    public ResponseEntity<Object> deleteAccount(HttpServletRequest request) {
        return userService.deleteAccount(request);
    }


}

class OtpRequest {
    private String otp;

    // Getters and setters
    public String getOtp() { return otp; }
    public void setOtp(String otp) { this.otp = otp; }
}