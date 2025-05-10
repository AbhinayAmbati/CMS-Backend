package com.portfolio.cms.Dao;

import com.portfolio.cms.Model.Image;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ImageDao extends JpaRepository<Image,Integer> {

}
