package com.portfolio.cms.Dao;


import com.portfolio.cms.Model.PasswordReset;
import com.portfolio.cms.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PasswordResetDao extends JpaRepository<PasswordReset, Long> {

    Optional<PasswordReset> findByToken(String token);

    void deleteByUser(User user);
}