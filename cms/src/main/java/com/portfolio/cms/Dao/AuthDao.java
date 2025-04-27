package com.portfolio.cms.Dao;

import com.portfolio.cms.Model.User;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthDao extends JpaRepository<User,Integer> {
    Optional<Object> findByEmail(String email);
}
