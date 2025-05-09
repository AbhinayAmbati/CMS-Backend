package com.portfolio.cms.Service;

import com.portfolio.cms.Dao.AuthDao;
import com.portfolio.cms.Model.User;
import com.portfolio.cms.config.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Configuration
@Service
public class AuthService {

    @Autowired
    AuthDao authDao;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Autowired
    JwtUtil jwtUtil;

    public ResponseEntity<Object> signUp(String email, String firstName, String lastName, String password) {
        try {
            if (authDao.findByEmail(email).isPresent()) {
                return new ResponseEntity<>(email + " is already registered.", HttpStatus.CONFLICT);
            }

            if(email == null || firstName == null || lastName == null || password == null) {
                return new ResponseEntity<>("Null values are passed",HttpStatus.BAD_REQUEST);
            }

            String hashedPassword = encoder.encode(password);

            // Create a new user and save it to the database
            User user = new User();
            user.setEmail(email);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setPassword(hashedPassword);
            authDao.save(user);

            return new ResponseEntity<>(user, HttpStatus.CREATED);

        } catch (Exception e) {
            // Handle errors gracefully
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> signIn(String email, String password) {
        try {
            Optional<Object> userData = authDao.findByEmail(email);
            if (userData.isEmpty()) {
                return new ResponseEntity<>(email + " is not registered.", HttpStatus.NOT_FOUND);
            }

            User user = (User) userData.get();

            if (!encoder.matches(password, user.getPassword())) {
                return new ResponseEntity<>("Incorrect Password", HttpStatus.UNAUTHORIZED);
            }

            // Create authorities list based on admin flag
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // All users get USER role

            // Add ADMIN role if user is an admin
            if (user.isAdmin()) {
                authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }

            // Create UserDetails object
            UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                    user.getEmail(),
                    user.getPassword(),
                    authorities
            );

            // Generate JWT with authorities included
            String jwtToken = jwtUtil.generateToken(userDetails);

            // Response wrapper class
            class JwtResponse {
                private String jwtToken;
                private User user;
                private boolean isAdmin;

                public JwtResponse(String jwtToken, User user, boolean isAdmin) {
                    this.jwtToken = jwtToken;
                    this.user = user;
                    this.isAdmin = isAdmin;
                }

                public String getJwtToken() {
                    return jwtToken;
                }

                public void setJwtToken(String jwtToken) {
                    this.jwtToken = jwtToken;
                }

                public User getUser() {
                    return user;
                }

                public void setUser(User user) {
                    this.user = user;
                }

                public boolean isAdmin() {
                    return isAdmin;
                }

                public void setAdmin(boolean admin) {
                    isAdmin = admin;
                }
            }

            JwtResponse jwtResponse = new JwtResponse(jwtToken, user, user.isAdmin());
            return ResponseEntity.ok(jwtResponse);

        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
