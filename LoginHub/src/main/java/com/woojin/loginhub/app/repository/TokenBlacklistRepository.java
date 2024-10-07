package com.woojin.loginhub.app.repository;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

@Repository
public class TokenBlacklistRepository {

    private final RedisTemplate<String, String> redisTemplate;
    private static final String BLACKLIST = "blacklisted";

    public TokenBlacklistRepository(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void addTokenToBlacklist(String token, long expirationTime) {
        redisTemplate.opsForValue().set(token, BLACKLIST, expirationTime, TimeUnit.MILLISECONDS);
    }

    public boolean isTokenBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }
}
