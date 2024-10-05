package com.woojin.loginhub.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "USERS")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "USER_ID")
    private Long id;

    private String email;
    private String password;
    private String nickName;
    private String imageUrl;
    private int age;
    private String city;

    private String refreshToken;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private SocialType socialType;

    private String socialId;

    public void authorizeUser() {
        this.role = Role.USER;
    }

    public void passwordEncode(PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(this.password);
    }

    public void updateRefreshToken(String UpdateRefreshToken) {
        this.refreshToken = UpdateRefreshToken;
    }

    // 생성자 제한을 걸어 불완전한 객체의 가능성을 차단한다.
    @Builder
    public User(Long id,
                String email, String password,
                String nickName, String imageUrl,
                int age, String city,
                String refreshToken, Role role,
                SocialType socialType, String socialId) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.nickName = nickName;
        this.imageUrl = imageUrl;
        this.age = age;
        this.city = city;
        this.refreshToken = refreshToken;
        this.role = role;
        this.socialType = socialType;
        this.socialId = socialId;
    }
}
