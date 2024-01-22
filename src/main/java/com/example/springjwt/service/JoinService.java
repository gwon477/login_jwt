//package com.example.springjwt.service;
//
//import com.example.springjwt.constant.Role;
//import com.example.springjwt.dto.JoinDTO;
//import com.example.springjwt.entity.UserEntity;
//import com.example.springjwt.repository.UserRepository;
//import org.apache.catalina.User;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
//import java.time.LocalDateTime;
//
//@Service
//public class JoinService {
//
//    private final UserRepository userRepository;
//    //private final BCryptPasswordEncoder bCryptPasswordEncoder;
//
//    private final PasswordEncoder passwordEncoder;
//
//    public JoinService(UserRepository userRepository,PasswordEncoder passwordEncoder) {
//
//        this.userRepository = userRepository;
//       //this.bCryptPasswordEncoder = bCryptPasswordEncoder;
//        this.passwordEncoder = passwordEncoder;
//    }
//
//    public void joinProcess(JoinDTO joinDTO) {
//
//        String username = joinDTO.getUsername();
//        String password = joinDTO.getPassword();
//        String email = joinDTO.getEmail();
//
//        //Boolean isExist = userRepository.existsByUsername(username);
//        Boolean isExist = userRepository.existsByUserEmail(email);
//
//        if (isExist) {
//
//            return;
//        }
//
//        UserEntity user1 = UserEntity.builder()
//                .userEmail(email)
//                .password(passwordEncoder.encode(password))
//                .userName(username)
//                .userJoinDate(LocalDateTime.now())
//                .userPhoneNum("010-1111-1111")
//                .userPostalCode(12345)
//                .userAddress("Seoul")
//                .userAddressDetail("Apartment 123")
//                .build();
//
//        user1.setUserRole(Role.ROLE_PM);
//
//        userRepository.save(user1);
//    }
//}
