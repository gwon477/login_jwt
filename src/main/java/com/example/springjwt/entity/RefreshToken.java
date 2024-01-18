package com.example.springjwt.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;

@Entity
@Table(name="tb_refresh_token")
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long refreshTokenId;
//
//    @Column(nullable = false)
//    private Long userId;

    @Column(nullable = false)
    private String userEmail;

    @Column(nullable = false)
    private String refreshToken;

    @CreatedDate
    private LocalDateTime refreshTokenexpiredDate;
}
