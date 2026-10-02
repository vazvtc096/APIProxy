package com.apiproxy.repository;

import com.apiproxy.entity.PostCollection;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostCollectionRepository extends JpaRepository<PostCollection, Integer> {
}
