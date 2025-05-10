package com.portfolio.cms.Dao;

import com.portfolio.cms.Model.Content;
import com.portfolio.cms.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ContentDao extends JpaRepository<Content, Integer> {
    List<Content> findByAuthor(User author);
    List<Content> findByAuthorId(Integer authorId);
    List<Content> findByTitleContainingIgnoreCase(String title);
}