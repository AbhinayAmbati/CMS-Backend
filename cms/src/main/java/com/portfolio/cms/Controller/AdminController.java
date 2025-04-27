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

    @GetMapping("/getAllUsers")
    public ResponseEntity<Object> getAllUsers() {
        return adminService.getAllUsers();
    }
}
