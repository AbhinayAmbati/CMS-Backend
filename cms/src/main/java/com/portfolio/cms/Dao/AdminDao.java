package com.portfolio.cms.Dao;

import com.portfolio.cms.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdminDao extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);

}
