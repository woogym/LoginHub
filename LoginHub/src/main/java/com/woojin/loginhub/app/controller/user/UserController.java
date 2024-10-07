package com.woojin.loginhub.app.controller.user;

import com.woojin.loginhub.app.dto.user.UserSignUpDto;
import com.woojin.loginhub.app.service.login.SignUpService;
import com.woojin.loginhub.global.common.dto.ApiResponseTemplate;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final SignUpService signUpService;

    @PostMapping("/sign-up")
    public ResponseEntity<ApiResponseTemplate<UserSignUpDto>> signUp(@RequestBody UserSignUpDto userSignUpDto) throws Exception {
        ApiResponseTemplate<UserSignUpDto> data = signUpService.signUp(userSignUpDto);

        return ResponseEntity.status(data.getStatus()).body(data);
    }
}
