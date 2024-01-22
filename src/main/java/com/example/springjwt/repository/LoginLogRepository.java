package com.example.springjwt.repository;

import com.example.springjwt.entity.LoginLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginLogRepository extends JpaRepository<LoginLog, Long> {

}
