package com.woojin.loginhub.service.TokenService;

import com.woojin.loginhub.domain.User;
import com.woojin.loginhub.global.exception.ErrorCode;
import com.woojin.loginhub.global.exception.model.CustomException;
import com.woojin.loginhub.repository.TokenBlacklistRepository;
import com.woojin.loginhub.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Getter
@Slf4j
public class TokenProvider {

    private final Key key;
    private final long accessTokenValidityTime;
    private final long refreshTokenValidityTime;
    private final TokenBlacklistRepository tokenBlackListRepository;
    private final UserRepository userRepository;

    public TokenProvider(TokenBlacklistRepository tokenBlackListRepository, UserRepository userRepository,
                         @Value("${jwt.access.expiration}") long accessTokenValidityTime,
                         @Value("${jwt.refresh.expiration}") long refreshTokenValidityTime,
                         @Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenValidityTime = accessTokenValidityTime;
        this.refreshTokenValidityTime = refreshTokenValidityTime;
        this.tokenBlackListRepository = tokenBlackListRepository;
        this.userRepository = userRepository;
    }

    private static final String BEARER = "Bearer ";
    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String ROLE_CLAIM = "Role";
    private static final String AUTHORIZATION = "Authorization";

    public String createAccessToken(User user) {
        long nowTime = (new Date().getTime());
        Date accessTokenExpiredTime = new Date(nowTime + accessTokenValidityTime);

        return Jwts.builder()
                .setSubject(ACCESS_TOKEN_SUBJECT)
                .claim(ROLE_CLAIM, user.getRole().getKey())
                .claim(EMAIL_CLAIM, user.getEmail())
                .signWith(key, SignatureAlgorithm.ES512)
                .compact();
    }

    public String createRefreshToken() {
        long nowTime = (new Date().getTime());
        Date refreshTokenExpiredTime = new Date(nowTime + refreshTokenValidityTime);

        return Jwts.builder()
                .setSubject(REFRESH_TOKEN_SUBJECT)
                .setIssuedAt(new Date())
                .setExpiration(refreshTokenExpiredTime)
                .signWith(key, SignatureAlgorithm.ES512)
                .compact();
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new CustomException(ErrorCode.EXPIRED_TOKEN_EXCEPTION, "토큰이 만료되었습니다.");
        } catch (UnsupportedJwtException | SignatureException e) {
            throw new CustomException(ErrorCode.INVALID_TOKEN_EXCEPTION, "유효하지 않은 토큰입니다");
        }
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        if (claims.get("Role") == null) {
            throw new CustomException(ErrorCode.FORBIDDEN_AUTH_EXCEPTION, "권한이 없습니다.");
        }

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get("Role").toString().split(","))
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(claims.getSubject(), "", authorities);
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER)) {
            return bearerToken.substring(7);
        }

        return null;
    }

    public boolean validateToken(String token) {
        try {
            // 블랙리스트에 있는지 확인
            if (tokenBlackListRepository.isTokenBlacklisted(token)) {
                return false;
            }

            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
