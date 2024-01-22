package com.example.springjwt.config;
import com.example.springjwt.jwt.JWTFilter;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.jwt.LoginFilter;
import com.example.springjwt.repository.LoginLogRepository;
import com.example.springjwt.repository.RefreshTokenRepository;
import com.example.springjwt.repository.UserRepository;
import com.example.springjwt.service.LogoutService;
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
                .addFilterBefore(new JWTFilter(jwtUtil, userRepository, refreshTokenRepository), LoginFilter.class);

        // 로그인 필터 커스텀
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil,refreshTokenRepository,loginLogRepository), UsernamePasswordAuthenticationFilter.class);

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
