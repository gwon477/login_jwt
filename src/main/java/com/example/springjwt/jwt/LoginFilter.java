package com.example.springjwt.jwt;

import com.example.springjwt.dto.CMResDto;
import com.example.springjwt.dto.CustomUserDetails;
import com.example.springjwt.dto.TokenResponseDto;
import com.example.springjwt.entity.LoginLog;
import com.example.springjwt.entity.RefreshToken;
import com.example.springjwt.entity.RefreshTokenRedis;
import com.example.springjwt.repository.LoginLogRepository;
import com.example.springjwt.repository.RefreshTokenRedisRepository;
import com.example.springjwt.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Iterator;


public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginLogRepository loginLogRepository;

    //***************
    private final RefreshTokenRedisRepository refreshTokenRedisRepository;


    public LoginFilter(AuthenticationManager authenticationManager,
                       JWTUtil jwtUtil,
                       RefreshTokenRepository refreshTokenRepository,
                       LoginLogRepository loginLogRepository,
                       RefreshTokenRedisRepository refreshTokenRedisRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository=refreshTokenRepository;
        this.loginLogRepository = loginLogRepository;
        this.refreshTokenRedisRepository = refreshTokenRedisRepository;
        setFilterProcessesUrl("/api/users/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 로그인 요청 API 에서 username 값을 추출
        String username = obtainUsername(request);

        // 로그인 요청 API 에서 password 값을 추출
        String password = obtainPassword(request);

        // 로그인 요청 API 에서 useremaul 값을 추출
        String useremail = request.getParameter("email");

        System.out.println("login-1. password = " + password);
        System.out.println("login-1. useremail = " + useremail);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(useremail, password, null);

        return authenticationManager.authenticate(authToken);
    }

    private ObjectMapper objectMapper = new ObjectMapper();

    // 요청받은 정보가 DB에 있는 사용자인 경우
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();
        String email = customUserDetails.getEmail();

        LoginLog loginLog = new LoginLog();
        loginLog.setLoginLogContents(username);
        loginLogRepository.save(loginLog);

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        // AccessToken 만료 시간 6분
        String accesstoken = jwtUtil.createAccessJwt( email, role);

        // RefreshToken 만료 시간 24시간
        String refreshtoken = jwtUtil.createRefreshJwt(email,role);
        System.out.println("7!");
        saveRefreshTokenToDatabase(email,refreshtoken);

        // redis 적용해보기
        refreshTokenRedisRepository.save(new RefreshTokenRedis(refreshtoken,accesstoken, email));

        TokenResponseDto tokenResponseDto = new TokenResponseDto();
        tokenResponseDto.setAccesstoken(accesstoken);
        tokenResponseDto.setRefreshtoken(refreshtoken);

        CMResDto<TokenResponseDto> cmRespDto = CMResDto.<TokenResponseDto>builder()
                .code(200)
                .msg("Success")
                .data(tokenResponseDto)
                .build();

        // HttpServletRequest 에 body에 정보를 담기.
        writeResponse(response, cmRespDto);

        response.addHeader("Authorization", "Bearer " + accesstoken);
    }

    // 요청받은 정보가 DB에 없는 사용자인 경우
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        CMResDto<Void> cmRespDto = CMResDto.<Void>builder()
                .code(HttpServletResponse.SC_UNAUTHORIZED) // 401 Unauthorized
                .msg("아이디 또는 비밀번호가 틀렸습니다.")
                .build();

        // Write error response to the response body
        writeResponse(response, cmRespDto);
        response.setStatus(401);
    }

    private void saveRefreshTokenToDatabase(String userEmail, String refreshToken) {
        RefreshToken refreshTokendata = new RefreshToken();
        refreshTokendata.setUserEmail(userEmail);
        refreshTokendata.setRefreshToken(refreshToken);

        refreshTokenRepository.save(refreshTokendata);
    }

    private void writeResponse(HttpServletResponse response, CMResDto<?> cmRespDto) {
        try {
            // cmRespDto 객체로 변환해서 타입 반환.
            ObjectMapper objectMapper = new ObjectMapper();

            // cmRespDto 내부에 LocalDatetime 형식 변환 설정.
            objectMapper.registerModule(new JavaTimeModule());
            objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            objectMapper.setDateFormat(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS"));

            // response body에 담기.
            String jsonResponse = objectMapper.writeValueAsString(cmRespDto);

            // response 타입지정.
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            // response 반환.
            response.getWriter().write(jsonResponse);

        } catch (IOException e) {
            // 에러 핸들링
            e.printStackTrace();
        }
    }

}
