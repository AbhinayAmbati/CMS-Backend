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

    @DeleteMapping("/deleteuser")
    public ResponseEntity<Object> deleteUser(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        return adminService.deleteUser(email);
    }

}
