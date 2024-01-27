package com.example.springjwt.repository;

import com.example.springjwt.entity.RefreshTokenRedis;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRedisRepository extends CrudRepository<RefreshTokenRedis,String> {
    Optional<RefreshTokenRedis> findByAccessToken(String accessToken);
    boolean existsById(String refreshToken);
    void deleteById(String refreshToken);
}
