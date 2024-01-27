package com.example.springjwt.service;

import com.example.springjwt.entity.RefreshTokenRedis;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.repository.RefreshTokenRedisRepository;
import com.example.springjwt.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {


    private final JWTUtil jwtUtil;

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenRedisRepository refreshTokenRedisRepository;


    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.Authentication authentication) {
        String authorization = request.getHeader("Authorization");
        String token = authorization.split(" ")[1];
        System.out.println("token = " + token);

        //refreshTokenRepository.deleteByUserEmail(email);

        Optional<RefreshTokenRedis> refreshTokenRedis = refreshTokenRedisRepository.findByAccessToken(token);
        if(refreshTokenRedis.isPresent()){
            refreshTokenRedisRepository.deleteById(refreshTokenRedis.get().getRefreshToken());
        }else{

        }
    }
}
