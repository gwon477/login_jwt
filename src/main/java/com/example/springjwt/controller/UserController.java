package com.example.springjwt.controller;

import com.example.springjwt.dto.CMResDto;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.repository.RefreshTokenRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @GetMapping("/user")
    public String userP() {
        return "User Page";
    }

    @GetMapping("/admin/GM")
    public String adminGMP() {
        return "Admin GM Page";
    }
    @GetMapping("/admin/PM")
    public String adminPMP() {
        return "Admin PM Page";
    }
    @GetMapping("/admin/SM")
    public String adminSMP() {
        return "Admin SM Page";
    }

    @GetMapping("/user/a")
    public String testP(){return "test success";}

}
