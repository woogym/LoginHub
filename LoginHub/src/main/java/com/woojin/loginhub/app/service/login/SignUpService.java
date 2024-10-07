package com.woojin.loginhub.app.service.login;

import com.woojin.loginhub.app.domain.Role;
import com.woojin.loginhub.app.domain.User;
import com.woojin.loginhub.app.dto.user.UserSignUpDto;
import com.woojin.loginhub.app.repository.UserRepository;
import com.woojin.loginhub.global.common.dto.ApiResponseTemplate;
import com.woojin.loginhub.global.exception.ErrorCode;
import com.woojin.loginhub.global.exception.model.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class SignUpService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public ApiResponseTemplate<UserSignUpDto> signUp(UserSignUpDto userSignUpDto) throws Exception{

        if (userRepository.findByEmail(userSignUpDto.getEmail()).isPresent()) {
            throw new CustomException(ErrorCode.ALREADY_EXIT_EMAIL_EXCEPTION,
                    ErrorCode.ALREADY_EXIT_EMAIL_EXCEPTION.getMessage());
        }

        if (userRepository.findByEmail(userSignUpDto.getNickName()).isPresent()) {
            throw new CustomException(ErrorCode.ALREADY_EXIT_NICKNAME_EXCEPTION,
                    ErrorCode.ALREADY_EXIT_NICKNAME_EXCEPTION.getMessage());
        }

        User user = User.builder()
                .email(userSignUpDto.getEmail())
                .password(userSignUpDto.getPassword())
                .nickName(userSignUpDto.getNickName())
                .age(userSignUpDto.getAge())
                .city(userSignUpDto.getCity())
                .role(Role.USER)
                .build();

        user.passwordEncode(passwordEncoder);
        userRepository.save(user);

        return ApiResponseTemplate.<UserSignUpDto>builder()
                .status(200)
                .success(true)
                .message("회원가입 성공")
                .data(userSignUpDto)
                .build();
    }
}
