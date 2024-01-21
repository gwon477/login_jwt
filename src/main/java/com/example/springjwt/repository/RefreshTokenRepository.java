package com.example.springjwt.repository;

import com.example.springjwt.entity.RefreshToken;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {
    Boolean existsByRefreshToken(String token);
    @Transactional
    void deleteByUserEmail(String email);
}
