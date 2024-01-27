package com.example.springjwt.jwt;

import com.example.springjwt.constant.Role;
import com.example.springjwt.dto.CMResDto;
import com.example.springjwt.dto.CustomUserDetails;
import com.example.springjwt.dto.TokenResponseDto;
import com.example.springjwt.entity.RefreshToken;
import com.example.springjwt.entity.RefreshTokenRedis;
import com.example.springjwt.entity.UserEntity;
import com.example.springjwt.repository.RefreshTokenRedisRepository;
import com.example.springjwt.repository.RefreshTokenRepository;
import com.example.springjwt.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.security.auth.Subject;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.Objects;


public class JWTFilter extends OncePerRequestFilter {

    @Value("${spring.jwt.expireT}")
    private Long jwtExpiration;

    @Value("${spring.jwt.ReFreshexpireT}")
    private Long RefreshjwtExpiration;

    private final JWTUtil jwtUtil;

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final RefreshTokenRedisRepository refreshTokenRedisRepository;


    public JWTFilter(JWTUtil jwtUtil,UserRepository userRepository,RefreshTokenRepository refreshTokenRepository,RefreshTokenRedisRepository refreshTokenRedisRepository){
        this.jwtUtil=jwtUtil;
        this.refreshTokenRepository=refreshTokenRepository;
        this.userRepository=userRepository;
        this.refreshTokenRedisRepository=refreshTokenRedisRepository;
    }

    @Override
    @Transactional
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");
        System.out.println("authorization = " + authorization);

        //Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }
        // 헤더가 있기 때문에 헤더를 추출
        String token = authorization.split(" ")[1];
        System.out.println("token = " + token);

        // 헤더가 만료되었는 확인
        try {
            jwtUtil.isExpired(token);
        } catch (ExpiredJwtException e) {

            System.out.println("token expired");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            CMResDto<Void> cmRespDto = CMResDto.<Void>builder()
                    .code(HttpServletResponse.SC_UNAUTHORIZED) // 401 Unauthorized
                    .msg("토큰이 만료되었습니다.")
                    .build();

            writeResponse(response, cmRespDto);

            //filterChain.doFilter(request, response);
            return;
        }


        String type = jwtUtil.getType(token);
        System.out.println("1.type = " + type);

        String email = jwtUtil.getEmail(token);
        System.out.println("1.email = " + email);
        String role = jwtUtil.getRole(token);

        if(Objects.equals(type, "RTK")){
            if(refreshTokenRedisRepository.existsById(token)){
                System.out.println("YES");
                refreshTokenRedisRepository.deleteById(token);
                String newAccessToken = jwtUtil.createAccessJwt(email,role);
                String newRefreshtoken = jwtUtil.createRefreshJwt(email,role);
                refreshTokenRedisRepository.save(new RefreshTokenRedis(newRefreshtoken,newAccessToken, email));
                System.out.println("ALLRIGHT");


                TokenResponseDto tokenResponseDto = new TokenResponseDto();
                tokenResponseDto.setAccesstoken(newAccessToken);
                tokenResponseDto.setRefreshtoken(newRefreshtoken);

                CMResDto<TokenResponseDto> cmRespDto = CMResDto.<TokenResponseDto>builder()
                        .code(200)
                        .msg("새로운 토큰 발급 Success")
                        .data(tokenResponseDto)
                        .build();

                writeResponse(response, cmRespDto);

                return;

            }else{
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                CMResDto<Void> cmRespDto = CMResDto.<Void>builder()
                        .code(HttpServletResponse.SC_UNAUTHORIZED) // 401 Unauthorized
                        .msg("Refresh토큰이 없습니다. 다시 로그인 해주세요")
                        .build();

                writeResponse(response, cmRespDto);

                //filterChain.doFilter(request, response);
                return;
            }
        }

        UserEntity userEntity = new UserEntity();
        userEntity.setUserName("username");
        userEntity.setPassword("temppassword");
        userEntity.setUserEmail(email);
        userEntity.setUserRole(Role.valueOf(role));
        userEntity.setUserMileage(1000);
        userEntity.setUserAddressDetail("AddressDetail");
        userEntity.setUserAddress("UserAddress");
        userEntity.setUserPostalCode(7);
        userEntity.setUserDktNum(777);
        userEntity.setUserPhoneNum("77-89");


        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }

    // JSON 응답을 생성하는 메소드
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
