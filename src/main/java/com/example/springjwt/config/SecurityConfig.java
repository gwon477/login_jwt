package com.example.springjwt.config;
import com.example.springjwt.jwt.JWTFilter;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.jwt.LoginFilter;
import com.example.springjwt.repository.LoginLogRepository;
//port com.example.springjwt.repository.RefreshTokenRedisRepository;
import com.example.springjwt.repository.RefreshTokenRedisRepository;
import com.example.springjwt.repository.RefreshTokenRepository;
import com.example.springjwt.repository.UserRepository;
import com.example.springjwt.service.LogoutService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    // 비밀번호 인코더
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }


    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final LogoutService logoutService;
    private final LoginLogRepository loginLogRepository;
    private final RefreshTokenRedisRepository refreshTokenRedisRepository;

    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_GM > ROLE_PM\n" +
                "ROLE_GM > ROLE_SM\n" +
                "ROLE_PM > ROLE_USER\n" +
                "ROLE_SM > ROLE_USER"
                );

        return hierarchy;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        // 연결된 프론트 주소
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        // 허용할 메서드 종류
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        // 헤더 종류에 따른 허용여부 결정
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);
                        // 토큰을 사용하기 때문에 인증도 허용
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                })));

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 접근 제한
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/api/users/login", "/", "/join").permitAll()
                        .requestMatchers("/admin/GM").hasRole("GM")
                        .requestMatchers("/admin/PM").hasRole("PM")
                        .requestMatchers("/admin/SM").hasRole("SM")
                        .requestMatchers("/user/**").hasRole("USER")
                        .anyRequest().authenticated()
                );


        // 로그인 필터 커스텀
        http
                .addFilterBefore(new JWTFilter(jwtUtil, userRepository, refreshTokenRepository,refreshTokenRedisRepository), LoginFilter.class);

        // 로그인 필터 커스텀
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil,refreshTokenRepository,loginLogRepository,refreshTokenRedisRepository), UsernamePasswordAuthenticationFilter.class);

        // 로그아웃 설정
        http
                .logout((logout) -> logout.logoutUrl("/logout")
                        .addLogoutHandler(logoutService)
                        .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                );

        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }



}
