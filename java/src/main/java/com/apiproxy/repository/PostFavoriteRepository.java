package com.apiproxy.repository;

import com.apiproxy.entity.PostFavorite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostFavoriteRepository extends JpaRepository<PostFavorite, Integer> {
}
