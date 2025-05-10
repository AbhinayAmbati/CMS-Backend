package com.portfolio.cms.Controller;

import com.portfolio.cms.Service.ImageService;
import com.portfolio.cms.config.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/image")
public class ImageController {

    @Autowired
    private ImageService imageService;

    @Autowired
    private JwtUtil jwtUtil; // Inject your JWT utility

    @PostMapping("/addimage")
    public ResponseEntity<Object> addImage(
            @RequestParam(value = "image", required = false) MultipartFile image,
            HttpServletRequest request) {

        // Extract and validate JWT token
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix
        if (!jwtUtil.validateToken(token)) {
            return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
        }

        // Proceed with image upload
        return imageService.addImage(image);
    }

    @GetMapping("/getimage/{id}")
    public ResponseEntity<Object> getImage(
            @PathVariable Integer id,
            HttpServletRequest request) {

        // Extract and validate JWT token
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>("Authorization header missing or invalid", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix
        if (!jwtUtil.validateToken(token)) {
            return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
        }

        // Proceed with getting image
        return imageService.getImage(id);
    }
}