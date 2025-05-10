package com.portfolio.cms.Service;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import com.portfolio.cms.Dao.ImageDao;
import com.portfolio.cms.Model.Image;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;
import java.util.Optional;

@Configuration
@Service
public class ImageService {

    @Autowired
    Cloudinary cloudinary;
    @Autowired
    private ImageDao imageDao;

    public ResponseEntity<Object> addImage(MultipartFile image) {
        try {
            if (image == null || image.isEmpty()) {
                return ResponseEntity.badRequest().body("No image provided");
            }

            // Upload to Cloudinary
            Map uploadResult = cloudinary.uploader().upload(
                    image.getBytes(),
                    ObjectUtils.asMap("resource_type", "auto")
            );

            String imageUrl = (String) uploadResult.get("secure_url");

            // Create and save image object
            Image imageObj = new Image();
            imageObj.setImageUrl(imageUrl);
            imageDao.save(imageObj);

            // EditorJS expects the direct URL as a string response
            return ResponseEntity.ok(imageUrl);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error uploading image: " + e.getMessage());
        }
    }

    public ResponseEntity<Object> getImage(Integer id) {
        try {
            Optional<Image> imageOpt = imageDao.findById(id);

            if (imageOpt.isPresent()) {
                Image image = imageOpt.get();
                return ResponseEntity.ok(image.getImageUrl());
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("Image not found with id: " + id);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error fetching image: " + e.getMessage());
        }
    }
}