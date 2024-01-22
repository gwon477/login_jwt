package com.example.springjwt.entity;

import com.example.springjwt.constant.Role;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;

@Entity
@Table(name="tb_login_log")
@Getter
@Setter
@NoArgsConstructor
public class LoginLog{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long loginLogId;

    @Column(nullable = false)
    private LocalDateTime loginLogCreatedDate = LocalDateTime.now();

    @Column(nullable = false, columnDefinition="TEXT")
    private String loginLogContents;

}