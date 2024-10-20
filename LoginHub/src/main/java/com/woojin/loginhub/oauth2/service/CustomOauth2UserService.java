package com.woojin.loginhub.oauth2.service;

import com.woojin.loginhub.app.domain.SocialType;
import com.woojin.loginhub.app.domain.User;
import com.woojin.loginhub.app.repository.UserRepository;
import com.woojin.loginhub.oauth2.CustomOauth2User;
import com.woojin.loginhub.oauth2.OauthAttributes;
import java.util.Collections;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOauth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    private static final String NAVER = "naver";
    private static final String KAKAO = "kakao";

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        OauthAttributes extractAttributes = OauthAttributes.of(socialType, userNameAttributeName, attributes);

        User user = getUserEntity(extractAttributes, socialType);

        return new CustomOauth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRole().getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                user.getEmail(),
                user.getRole()
        );
    }

    private SocialType getSocialType(String registrationId) {
        if (NAVER.equals(registrationId)) {
            return SocialType.NAVER;
        }
        if (KAKAO.equals(registrationId)) {
            return SocialType.KAKAO;
        }

        return SocialType.GOOGLE;
    }

    private User getUserEntity(OauthAttributes attributes, SocialType socialType) {
        User user = userRepository.findBySocialTypeAndSocialId(socialType,
                attributes.getOauth2UserInfo().getId()).orElse(null);

        if (user == null) {
            return saveUser(attributes, socialType);
        }

        return user;
    }

    private User saveUser(OauthAttributes attributes, SocialType socialType) {
        User createUser = attributes.toDomain(socialType, attributes.getOauth2UserInfo());

        return userRepository.save(createUser);
    }
}
