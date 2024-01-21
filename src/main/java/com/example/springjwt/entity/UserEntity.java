package com.example.springjwt.entity;

import com.example.springjwt.constant.Role;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Set;

@Entity
@Setter
@Getter
@Table(name="default_user")
@NoArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer userId;

    @Column(nullable = false)
    private String userEmail;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String userName;

    private Integer userDktNum;

    //@CreatedDate  //보류
    private LocalDateTime userRegisterDate; //가입일

    private LocalDateTime userJoinDate; //입사일

    private Integer userMileage;

    private String userPhoneNum;

    private Integer userPostalCode;

    private String userAddress;

    private String userAddressDetail;

    private Role userRole;

    public void setUserRole(Role userRole) {
        this.userRole = userRole;
    }



    @Builder
    public UserEntity(String userEmail, Integer userDktNum, String password, String userName, LocalDateTime userJoinDate, String userPhoneNum, Integer userPostalCode, String userAddress, String userAddressDetail) {
        this.userEmail = userEmail;
        this.password = password;

        this.userDktNum = userDktNum;
        this.userName = userName;
        this.userPhoneNum = userPhoneNum;
        this.userMileage = 0;  //초기 마일리지는 0원으로 설정
        this.userRole = Role.ROLE_USER;  //초기 Role은 USER로 설정

        this.userJoinDate = userJoinDate;
        this.userRegisterDate = LocalDateTime.now().withNano(0);

        this.userPostalCode = userPostalCode;
        this.userAddress = userAddress;
        this.userAddressDetail = userAddressDetail;
    }
}
