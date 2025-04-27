package com.portfolio.cms.Controller;

import com.portfolio.cms.Model.User;
import com.portfolio.cms.Service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class AuthController {

    @Autowired
    AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<Object> signUp(@RequestBody User user){
        return authService.signUp(
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getPassword()
        );
    }

    @PostMapping("/signin")
    public ResponseEntity<Object> signIn(@RequestBody User user){
        return authService.signIn(
                user.getEmail(),
                user.getPassword()
        );
    }
}
