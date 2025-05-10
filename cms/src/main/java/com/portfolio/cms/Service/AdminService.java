package com.portfolio.cms.Service;

import com.portfolio.cms.Dao.AdminDao;
import com.portfolio.cms.Model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Configuration
@Service
public class AdminService {

    @Autowired
    AdminDao adminDao;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;


    public ResponseEntity<Object> getAllUsers() {
        List<User> users = adminDao.findAll(); // Assuming findAll() returns a List of users
        if (users.isEmpty()) {
            return new ResponseEntity<>("No users found", HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(users, HttpStatus.OK); // Return users with a 200 OK status
    }

    public ResponseEntity<Object> deleteUser(String email) {
        try {
            // Remove the cast to User
            Optional<User> userOptional = adminDao.findByEmail(email);

            if (userOptional.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userOptional.get();
            adminDao.delete(user);
            return new ResponseEntity<>("User deleted successfully", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error deleting user: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> addUser(String email, String username, String password) {
        try {
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setUsername(username);
            newUser.setPassword(password);
            newUser.setAdmin(false);

            adminDao.save(newUser);
            return new ResponseEntity<>("User added successfully", HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>("Error adding user: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> updateUser(String email,String newEmail, String username, String password, String admin, String verified) {
        try {
            Optional<User> userOptional = adminDao.findByEmail(email);

            if (userOptional.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userOptional.get();

            if(newEmail != null && !newEmail.isEmpty() && !newEmail.equals(user.getEmail())) {
                user.setEmail(newEmail);
            }

            if(username != null && !username.isEmpty()) {
                user.setUsername(username);
            }


            if(password != null && !password.isEmpty() && !password.equals(user.getPassword())) {
                String hashedPassword = passwordEncoder.encode(password);
                user.setPassword(hashedPassword);
            }

            user.setAdmin(admin != null && admin.equals("true"));

            user.setVerified(verified != null && verified.equals("true"));

            adminDao.save(user);
            return new ResponseEntity<>("User updated successfully", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error updating user: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
