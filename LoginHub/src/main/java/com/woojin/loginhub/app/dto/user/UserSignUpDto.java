package com.woojin.loginhub.app.dto.user;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class UserSignUpDto {

    private String email;
    private String password;
    private String nickName;
    private int age;
    private String city;
}
