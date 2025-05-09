package com.portfolio.cms.Dao;

import com.portfolio.cms.Model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface VerificationTokenDao extends JpaRepository<VerificationToken, Long> {
    Optional<VerificationToken> findByEmail(String email);
    Optional<VerificationToken> findByEmailAndToken(String email, String token);
    void deleteByEmail(String email);

    void delete(VerificationToken verificationToken);

}