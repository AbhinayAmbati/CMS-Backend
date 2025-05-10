package com.portfolio.cms.Controller;

import com.portfolio.cms.Service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    AdminService adminService;

    @GetMapping("/getallusers")
    public ResponseEntity<Object> getAllUsers() {
        try {
            return adminService.getAllUsers();
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal Server Error: " + e.getMessage());
        }
    }

    @PostMapping("/adduser")
    public ResponseEntity<Object> addUser(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String username = request.get("username");
        String password = request.get("password");
        return adminService.addUser(email, username, password);
    }

    @PostMapping("/updateuser")
    public ResponseEntity<Object> updateUser(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String newEmail = request.get("newEmail");
        String username = request.get("username");
        String password = request.get("password");
        String admin = request.get("admin");
        String verified = request.get("verified");
        return adminService.updateUser(email,newEmail, username, password, admin, verified);
    }

    @DeleteMapping("/deleteuser")
    public ResponseEntity<Object> deleteUser(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        return adminService.deleteUser(email);
    }

}
