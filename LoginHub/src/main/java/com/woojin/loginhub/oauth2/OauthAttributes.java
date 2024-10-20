package com.woojin.loginhub.oauth2;

import com.woojin.loginhub.app.domain.Role;
import com.woojin.loginhub.app.domain.SocialType;
import com.woojin.loginhub.app.domain.User;
import com.woojin.loginhub.oauth2.userinfo.GoogleOauth2UserInfo;
import com.woojin.loginhub.oauth2.userinfo.KakaoOauth2UserInfo;
import com.woojin.loginhub.oauth2.userinfo.NaverOauth2UserInfo;
import com.woojin.loginhub.oauth2.userinfo.Oauth2UserInfo;
import java.util.Map;
import java.util.UUID;
import lombok.Builder;
import lombok.Getter;

@Getter
public class OauthAttributes {

    private final String nameAttributeKey;
    private final Oauth2UserInfo oauth2UserInfo;

    @Builder
    public OauthAttributes(String nameAttributeKey, Oauth2UserInfo oauth2UserInfo) {
        this.nameAttributeKey = nameAttributeKey;
        this.oauth2UserInfo = oauth2UserInfo;
    }

    public static OauthAttributes of(SocialType socialType,
                                     String userNameAttributeKey,
                                     Map<String, Object> attributes) {
        if (socialType == SocialType.NAVER) {
            return ofNaver(userNameAttributeKey, attributes);
        }
        if (socialType == SocialType.KAKAO) {
            return ofKakao(userNameAttributeKey, attributes);
        }

        return ofGoogle(userNameAttributeKey, attributes);
    }

    private static OauthAttributes ofKakao(String userNameAttributeKey,
                                           Map<String, Object> attributes) {
        return OauthAttributes.builder()
                .nameAttributeKey(userNameAttributeKey)
                .oauth2UserInfo(new KakaoOauth2UserInfo(attributes))
                .build();
    }

    private static OauthAttributes ofGoogle(String userNameAttributeKey,
                                            Map<String, Object> attributes) {
        return OauthAttributes.builder()
                .nameAttributeKey(userNameAttributeKey)
                .oauth2UserInfo(new GoogleOauth2UserInfo(attributes))
                .build();
    }

    private static OauthAttributes ofNaver(String userNameAttributeKey,
                                           Map<String, Object> attributes) {
        return OauthAttributes.builder()
                .nameAttributeKey(userNameAttributeKey)
                .oauth2UserInfo(new NaverOauth2UserInfo(attributes))
                .build();
    }

    public User toDomain(SocialType socialType, Oauth2UserInfo oauth2UserInfo) {
        return User.builder()
                .socialType(socialType)
                .socialId(oauth2UserInfo.getId())
                .email(UUID.randomUUID() + "@socialUser.com")
                .nickName(oauth2UserInfo.getNickname())
                .imageUrl(oauth2UserInfo.getImageUrl())
                .role(Role.GUEST)
                .build();
    }
}
