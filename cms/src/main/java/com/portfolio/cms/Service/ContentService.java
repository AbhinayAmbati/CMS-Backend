package com.portfolio.cms.Service;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.portfolio.cms.DTO.ContentDTO;
import com.portfolio.cms.Model.Content;
import com.portfolio.cms.Model.User;
import com.portfolio.cms.Dao.ContentDao;
import com.portfolio.cms.Dao.UserDao;
import com.portfolio.cms.config.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Transactional
@Service
public class ContentService {

    @Autowired
    private ContentDao contentDao;

    @Autowired
    private UserDao userDao;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private Cloudinary cloudinary;

    private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMMM d, yyyy");

    public ResponseEntity<Object> getAllContent() {
        try {
            List<Content> contents = contentDao.findAll();
            List<ContentDTO> contentDTOs = contents.stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(contentDTOs);
        } catch (Exception e) {
            return new ResponseEntity<>("Failed to retrieve content: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> getContentByAuthorId(Integer authorId) {
        try {
            List<Content> contents = contentDao.findByAuthorId(authorId);
            List<ContentDTO> contentDTOs = contents.stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(contentDTOs);
        } catch (Exception e) {
            return new ResponseEntity<>("Failed to retrieve content by author: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> getContentById(Integer id) {
        try {
            Optional<Content> content = contentDao.findById(id);
            if (content.isPresent()) {
                return ResponseEntity.ok(convertToDTO(content.get()));
            } else {
                return new ResponseEntity<>("Content not found with id: " + id,
                        HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) {
            return new ResponseEntity<>("Failed to retrieve content: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> createContent(String title, String excerpt, String data,
                                                MultipartFile image, HttpServletRequest request) {
        try {
            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid",
                        HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String userEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userOptional = userDao.findByEmail(userEmail);
            if (userOptional.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User author = userOptional.get();

            // Input validation
            if (title == null || title.isEmpty()) {
                return new ResponseEntity<>("Title is required", HttpStatus.BAD_REQUEST);
            }

            Content content = new Content();
            content.setTitle(title);
            content.setExcerpt(excerpt);
            content.setData(data);
            content.setAuthor(author);

            // Handle image upload if provided
            if (image != null && !image.isEmpty()) {
                try {
                    Map<String, Object> uploadResult = cloudinary.uploader()
                            .upload(image.getBytes(),
                                    Map.of("folder", "content_images"));

                    // Get and save the secure URL
                    String imageUrl = (String) uploadResult.get("secure_url");
                    content.setImage(imageUrl);
                } catch (Exception e) {
                    return new ResponseEntity<>("Error uploading image: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }

            Content savedContent = contentDao.save(content);
            return ResponseEntity.status(HttpStatus.CREATED).body(convertToDTO(savedContent));

        } catch (Exception e) {
            return new ResponseEntity<>("Failed to create content: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> updateContent(Integer id, String title, String excerpt,
                                                String data, MultipartFile image, HttpServletRequest request) {
        try {
            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid",
                        HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String userEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userOptional = userDao.findByEmail(userEmail);
            if (userOptional.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User authenticatedUser = userOptional.get();

            // Fetch content to update
            Optional<Content> existingContentOpt = contentDao.findById(id);
            if (existingContentOpt.isEmpty()) {
                return new ResponseEntity<>("Content not found with id: " + id,
                        HttpStatus.NOT_FOUND);
            }

            Content existingContent = existingContentOpt.get();

            // Authorization check - only allow author or admin to update
            if (!existingContent.getAuthor().getId().equals(authenticatedUser.getId()) && !authenticatedUser.isAdmin()) {
                return new ResponseEntity<>("You are not authorized to update this content",
                        HttpStatus.FORBIDDEN);
            }

            // Update fields if provided
            boolean contentModified = false;

            if (title != null && !title.isEmpty()) {
                existingContent.setTitle(title);
                contentModified = true;
            }

            if (excerpt != null) {
                existingContent.setExcerpt(excerpt);
                contentModified = true;
            }

            if (data != null) {
                existingContent.setData(data);
                contentModified = true;
            }

            // Handle image upload if provided
            if (image != null && !image.isEmpty()) {
                String oldImageUrl = existingContent.getImage();

                // Delete old image from Cloudinary if it exists
                if (oldImageUrl != null && !oldImageUrl.isEmpty()) {
                    try {
                        String publicId = oldImageUrl.substring(oldImageUrl.lastIndexOf("/") + 1,
                                oldImageUrl.lastIndexOf("."));
                        cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
                    } catch (Exception e) {
                        return new ResponseEntity<>("Error deleting old image: " + e.getMessage(),
                                HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                }

                try {
                    Map<String, Object> uploadResult = cloudinary.uploader()
                            .upload(image.getBytes(),
                                    Map.of("folder", "content_images"));

                    // Get and save the secure URL
                    String newImageUrl = (String) uploadResult.get("secure_url");
                    existingContent.setImage(newImageUrl);
                    contentModified = true;
                } catch (Exception e) {
                    return new ResponseEntity<>("Error uploading image: " + e.getMessage(),
                            HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }

            if (contentModified) {
                existingContent.setUpdatedAt(LocalDateTime.now());
                Content updatedContent = contentDao.save(existingContent);
                return ResponseEntity.ok(convertToDTO(updatedContent));
            } else {
                return ResponseEntity.ok("No changes made to content");
            }

        } catch (Exception e) {
            return new ResponseEntity<>("Failed to update content: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> deleteContent(Integer id, HttpServletRequest request) {
        try {
            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid",
                        HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String userEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userOptional = userDao.findByEmail(userEmail);
            if (userOptional.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User authenticatedUser = userOptional.get();

            // Fetch content to delete
            Optional<Content> contentOpt = contentDao.findById(id);
            if (contentOpt.isEmpty()) {
                return new ResponseEntity<>("Content not found with id: " + id,
                        HttpStatus.NOT_FOUND);
            }

            Content content = contentOpt.get();

            // Authorization check - only allow author or admin to delete
            if (!content.getAuthor().getId().equals(authenticatedUser.getId()) && !authenticatedUser.isAdmin()) {
                return new ResponseEntity<>("You are not authorized to delete this content",
                        HttpStatus.FORBIDDEN);
            }

            // Delete image from Cloudinary if it exists
            String imageUrl = content.getImage();
            if (imageUrl != null && !imageUrl.isEmpty()) {
                try {
                    String publicId = imageUrl.substring(imageUrl.lastIndexOf("/") + 1,
                            imageUrl.lastIndexOf("."));
                    cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
                } catch (Exception e) {
                    // Log the error but continue with deletion
                    System.err.println("Error deleting image from Cloudinary: " + e.getMessage());
                }
            }

            // Delete the content
            contentDao.deleteById(id);
            return ResponseEntity.ok("Content deleted successfully");

        } catch (Exception e) {
            return new ResponseEntity<>("Failed to delete content: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Object> getContentByUserToken(HttpServletRequest request) {
        try {
            // Authentication validation
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity<>("Authorization header missing or invalid",
                        HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            if (!jwtUtil.validateToken(token)) {
                return new ResponseEntity<>("Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Extract authenticated user's email from token
            String userEmail = jwtUtil.extractUsername(token);

            // Find the user in the database
            Optional<User> userOptional = userDao.findByEmail(userEmail);
            if (userOptional.isEmpty()) {
                return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
            }

            User user = userOptional.get();

            // Get content by author id
            List<Content> contents = contentDao.findByAuthorId(user.getId());
            List<ContentDTO> contentDTOs = contents.stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(contentDTOs);

        } catch (Exception e) {
            return new ResponseEntity<>("Failed to retrieve user content: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private ContentDTO convertToDTO(Content content) {
        ContentDTO dto = new ContentDTO();
        dto.setId(content.getId());
        dto.setTitle(content.getTitle());
        dto.setExcerpt(content.getExcerpt());
        dto.setAuthor(content.getAuthor().getUsername());
        dto.setAuthorId(content.getAuthor().getId());
        dto.setDate(content.getCreatedAt().format(formatter));
        dto.setImage(content.getImage());
        dto.setData(content.getData());

        // Add updated date if available
        if (content.getUpdatedAt() != null) {
            dto.setUpdatedAt(content.getUpdatedAt().format(formatter));
        }

        return dto;
    }
}