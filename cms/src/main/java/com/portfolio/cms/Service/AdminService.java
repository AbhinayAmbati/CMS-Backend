package com.portfolio.cms.Service;

import com.portfolio.cms.Dao.AdminDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Configuration
@Service
public class AdminService {

    @Autowired
    AdminDao adminDao;


    public ResponseEntity<Object> getAllUsers() {
        adminDao.findAll();
        return new ResponseEntity<>(HttpStatus.ACCEPTED);
    }
}
