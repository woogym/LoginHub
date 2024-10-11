package com.woojin.loginhub.global.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/*
스프링 시큐리티의 폼 기반 UserNamePasswordAuthenticationFilter 참고하여 만든 커스텀 필터
구조는 거의 동일하다, Type이 Json인 Login만 처리하도록 설정한 부분이 기존 동작과의 차이점이다 (커스텀 API용 필터 구현)
UserName : 회원 아이디 -> email로 설정 (소셜 로그인시에도 통요되도록 기본 Id를 email로 설정했다)
"/login" 요청이 왔을 때 JSON 값을 매핑 처리하는 필터
*/
public class CustomJsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String DEFAULT_LOGIN_REQUEST_URL = "/login";
    private static final String HTTP_METHOD = "POST";
    private static final String CONTENT_TYPE = "application/json";
    private static final String USERNAME_KEY = "email";
    private static final String PASSWORD_KEY = "password";
    private static final AntPathRequestMatcher DEFAULT_LOGIN_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher(DEFAULT_LOGIN_REQUEST_URL, HTTP_METHOD);

    private final ObjectMapper objectMapper;

    // 부모인 AbstractAuthenticationProcessingFilter의 생성자 파라미터로 상수 선언한 url을 넣어주었고
    // 이를 통해서 커스텀한 이 필터는 "/login" 경로로 들어올때만 작동하게 된다.
    public CustomJsonUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper) {
        super(DEFAULT_LOGIN_PATH_REQUEST_MATCHER);
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        if (request.getContentType() == null || !request.getContentType().equals(CONTENT_TYPE)) {
            throw new AuthenticationServiceException("Authentication Content-Type not supported: " + request.getContentType());
        }

        String messageBody = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);

        // Raw use of Parameterized class -> 제네릭 타입의 소거 관련 문제로 new TypeReference를 통해서 타입을 명시해줬고 이를 통해 런타임시에 castingException을 방지했다.
        Map<String, String> usernamePasswordMap = objectMapper.readValue(messageBody, new TypeReference<>() {
        });

        String email = usernamePasswordMap.get(USERNAME_KEY);
        String password = usernamePasswordMap.get(PASSWORD_KEY);

        UsernamePasswordAuthenticationToken authRequestToken = new UsernamePasswordAuthenticationToken(email, password);

        return this.getAuthenticationManager().authenticate(authRequestToken);
    }
}
