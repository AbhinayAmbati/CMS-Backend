package com.portfolio.cms.Controller;

import com.portfolio.cms.Service.ContentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/content")
public class ContentController {

    @Autowired
    private ContentService contentService;

    // Get all content
    @GetMapping("/getallcontent")
    public ResponseEntity<Object> getAllContent() {
        return contentService.getAllContent();
    }

    // Get content by id
    @GetMapping("/{id}")
    public ResponseEntity<Object> getContentById(@PathVariable Integer id) {
        return contentService.getContentById(id);
    }

    // Get content by author id
    @GetMapping("/author/{authorId}")
    public ResponseEntity<Object> getContentByAuthorId(@PathVariable Integer authorId) {
        return contentService.getContentByAuthorId(authorId);
    }

    // Get content by authenticated user
    @GetMapping("/user")
    public ResponseEntity<Object> getContentByUserToken(HttpServletRequest request) {
        return contentService.getContentByUserToken(request);
    }

    // Create new content
    @PostMapping("/addcontent")
    public ResponseEntity<Object> createContent(
            @RequestParam String title,
            @RequestParam(required = false) String excerpt,
            @RequestParam(required = false) String data,
            @RequestParam(required = false) MultipartFile image,
            HttpServletRequest request) {
        return contentService.createContent(title, excerpt, data, image, request);
    }

    // Update content
    @PutMapping("/update/{id}")
    public ResponseEntity<Object> updateContentPost(
            @PathVariable Integer id,
            @RequestParam(required = false) String title,
            @RequestParam(required = false) String excerpt,
            @RequestParam(required = false) String data,
            @RequestParam(required = false) MultipartFile image,
            HttpServletRequest request) {
        // Reuse the same service method
        return contentService.updateContent(id, title, excerpt, data, image, request);
    }

    // Delete content
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Object> deleteContent(@PathVariable Integer id, HttpServletRequest request) {
        return contentService.deleteContent(id, request);
    }
}