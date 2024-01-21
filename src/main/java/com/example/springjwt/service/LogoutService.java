package com.example.springjwt.service;

import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {


    private final JWTUtil jwtUtil;

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.Authentication authentication) {
        String authorization = request.getHeader("Authorization");
        String token = authorization.split(" ")[1];
        String email = jwtUtil.getEmail(token);

        refreshTokenRepository.deleteByUserEmail(email);


    }
}
