package com.example.springjwt.entity;


import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;


@Getter
@RedisHash(value = "refreshToken", timeToLive = 60*60*24*3)
public class RefreshTokenRedis {
    @Id
    private String refreshToken;
    @Indexed
    private String accessToken;
    private String email;

    public RefreshTokenRedis(String refreshToken, String accessToken,String email){
        this.email = email;
        this.refreshToken =refreshToken;
        this.accessToken = accessToken;
    }
}
