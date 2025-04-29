package com.portfolio.cms.Controller;

import com.portfolio.cms.Service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
            e.printStackTrace(); // <--- print the error
            return ResponseEntity.status(500).body("Internal Server Error: " + e.getMessage());
        }
    }

}
