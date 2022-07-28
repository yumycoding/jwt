package com.yumyapps.jwt.service;

import com.yumyapps.jwt.dto.TokenInformation;
import com.yumyapps.jwt.dto.UserUpgradeDto;
import com.yumyapps.jwt.models.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.List;

public interface AuthService {


    TokenInformation authenticateUser(String username, String password);

    public User updateUserInfo(UserUpgradeDto userDto, UsernamePasswordAuthenticationToken token);




}
