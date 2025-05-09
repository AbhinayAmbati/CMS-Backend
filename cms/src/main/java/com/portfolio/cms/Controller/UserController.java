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
    public ResponseEntity<Object> updateUserDetails(@RequestBody User user, MultipartFile image, HttpServletRequest request) {
        return userService.updateUserDetails(
                user.getUsername(),
                user.getEmail(),
                image,
                request
        );
    }
}
