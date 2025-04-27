package com.portfolio.cms.Service;

import com.portfolio.cms.Dao.AuthDao;
import com.portfolio.cms.Model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.Optional;


@Configuration
@Service
public class AuthService {

    @Autowired
    AuthDao authDao;

    @Autowired
    BCryptPasswordEncoder encoder;

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
        try{
            Optional<Object> userData = authDao.findByEmail(email);
            if(userData.isEmpty()) {
                return new ResponseEntity<>(email + " is not registered.", HttpStatus.NOT_FOUND);
            }

            User user = (User) userData.get();

            if(!encoder.matches(password, user.getPassword())) {
                return new ResponseEntity<>("Incorrect Password", HttpStatus.UNAUTHORIZED);
            }

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyGen.generateKeyPair();

            String jwtToken = Jwts.builder().setSubject(user.getEmail()).setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis()+3600000))
                    .signWith(SignatureAlgorithm.RS256,keyPair.getPrivate())
                    .compact();

            class JwtResponse{
                private String jwtToken;
                private User user;

                public JwtResponse(String jwtToken, User user) {
                    this.jwtToken = jwtToken;
                    this.user = user;
                }
                public String getJwtToken() {
                    return jwtToken;
                }
                public User getUser() {
                    return user;
                }
                public void setUser(User user) {
                    this.user = user;
                }
                public void setJwtToken(String jwtToken) {
                    this.jwtToken = jwtToken;
                }
                public String toString(String jwtToken, User user){
                    return jwtToken + " " + user;
                }
            }

            JwtResponse  jwtResponse = new JwtResponse(jwtToken,user);

            return ResponseEntity.ok(jwtResponse);

        }catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
