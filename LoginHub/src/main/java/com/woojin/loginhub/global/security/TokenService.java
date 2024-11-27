package com.woojin.loginhub.global.security;

import com.woojin.loginhub.app.domain.User;
import com.woojin.loginhub.global.exception.ErrorCode;
import com.woojin.loginhub.global.exception.model.CustomException;
import com.woojin.loginhub.app.repository.TokenBlacklistRepository;
import com.woojin.loginhub.app.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
@Getter
@Slf4j
public class TokenService {

    private final Key key;
    private final long accessTokenValidityTime;
    private final long refreshTokenValidityTime;
    private final TokenBlacklistRepository tokenBlackListRepository;
    private final UserRepository userRepository;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    public TokenService(TokenBlacklistRepository tokenBlackListRepository, UserRepository userRepository,
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
    private static final String ROLE = "Role";
    private static final String AUTHORIZATION = "Authorization";

    public String createAccessToken(String email) {
        long nowTime = (new Date().getTime());
        Date accessTokenExpiredTime = new Date(nowTime + accessTokenValidityTime);

        return Jwts.builder()
                .setSubject(ACCESS_TOKEN_SUBJECT)
                .claim(EMAIL_CLAIM, email)
                .setIssuedAt(new Date())
                .setExpiration(accessTokenExpiredTime)
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

    // 기존 로그인 방식에 초점을 둔 getAuthentication 로직
/*    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        if (claims.get(ROLE) == null) {
            throw new CustomException(ErrorCode.FORBIDDEN_AUTH_EXCEPTION, "권한이 없습니다.");
        }

        // 현재 권한을 관리할때 접두사로 Role이 붙어있기에 추가하는 접두사 추가 로직을 제거한다.
        // LoginService를 참고해보면 UserDetail객체의 roles를 빌드할때 내부동작 과정에서 "ROLE_"접두사를 붙여주기에 일관성있게 관리가 가능하다.
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(ROLE).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(claims.getSubject(), "", authorities);
    }*/

    // 현재 로그인 방식에 중점을 둔 새로운 getAuthentication 로직
/*    public Authentication getAuthentication(String token) {
        // 토큰에서 이메일을 추출하여 User 정보를 가져옴
        Claims claims = parseClaims(token);
        String email = claims.getSubject();

        // UserRepository에서 해당 이메일로 유저를 찾아옴
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException(ErrorCode.NOT_FOUND_USER_EXCEPTION, "유저를 찾을 수 없습니다."));

        // 유저의 정보를 기반으로 Authentication 객체를 생성
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())  // 비밀번호는 실제로 사용되지 않음
                .roles(user.getRole().name())  // 역할(Role) 설정
                .build();

        // Authentication 객체를 생성하여 반환
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }*/

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

    @Transactional
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        setAccessHeader(response, accessToken);
        log.info("재발급된 AccessToken : {}", accessToken);
    }

    @Transactional
    public void sendAccessAndRefreshToken(HttpServletResponse response,
                                          String accessToken, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        setAccessHeader(response, accessToken);
        setRefreshHeader(response, refreshToken);
        log.info("AccessToken, RefreshToken 헤더 설정 완료");
    }

    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(accessToken -> accessToken.startsWith(BEARER))
                .map(accessToken -> accessToken.replace(BEARER, ""));
    }

    public Optional<String> extractEmail(String accessToken) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();

            return Optional.ofNullable(claims.get(EMAIL_CLAIM, String.class));
        } catch (Exception e) {
            log.error("엑세스 토큰이 유효하지 않습니다.");
            throw new CustomException(ErrorCode.INVALID_TOKEN_EXCEPTION,
                    ErrorCode.INVALID_TOKEN_EXCEPTION.getMessage());
        }
    }

    // RefreshToken DB 저장
    public void updateRefreshToken(String email, String refreshToken) {
        userRepository.findByEmail(email)
                .ifPresentOrElse(
                        user -> user.updateRefreshToken(refreshToken),
                        () -> new CustomException(ErrorCode.NOT_FOUND_USER_EXCEPTION,
                                ErrorCode.NOT_FOUND_USER_EXCEPTION.getMessage())
                );
    }

    // 블랙리스트에 토큰 추가
    public void invalidateToken(String token) {
        tokenBlackListRepository.addTokenToBlacklist(token, refreshTokenValidityTime);
    }

    private void setAccessHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, accessToken);
    }

    private void setRefreshHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader, refreshToken);
    }
}
