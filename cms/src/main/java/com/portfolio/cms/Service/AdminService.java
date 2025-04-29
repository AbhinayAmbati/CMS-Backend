package com.portfolio.cms.Service;

import com.portfolio.cms.Dao.AdminDao;
import com.portfolio.cms.Model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Configuration
@Service
public class AdminService {

    @Autowired
    AdminDao adminDao;


    public ResponseEntity<Object> getAllUsers() {
        List<User> users = adminDao.findAll(); // Assuming findAll() returns a List of users
        if (users.isEmpty()) {
            return new ResponseEntity<>("No users found", HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(users, HttpStatus.OK); // Return users with a 200 OK status
    }

}
