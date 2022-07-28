package com.yumyapps.jwt.implmentation;

import com.yumyapps.jwt.dto.TokenInformation;
import com.yumyapps.jwt.dto.UserUpgradeDto;
import com.yumyapps.jwt.jwtutil.JwtTokenProvider;
import com.yumyapps.jwt.models.User;
import com.yumyapps.jwt.repository.UserRepository;
import com.yumyapps.jwt.security.UserPrincipal;
import com.yumyapps.jwt.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import static com.yumyapps.jwt.constants.Constants.JWT_TOKEN_HEADER;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImplementation implements AuthService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;


    @Override
    public TokenInformation authenticateUser(String username, String password) {

        authenticate(username, password);
        var loginUser = userRepository.findUserByUsername(username).get();
        var userPrincipal = new UserPrincipal(loginUser);
        var jwtHeader = getJwtHeader(userPrincipal);
        var information = getJwtInfo(userPrincipal);
        information.setHeader(jwtHeader);
        log.info("{} authenticated successfully.", username);
        return information;
    }


    @Override
    public User updateUserInfo(UserUpgradeDto userDto, UsernamePasswordAuthenticationToken token) {
        try {
            var userPrinciple = token.getPrincipal().toString();
            var user = userRepository.findUserByUsername(userPrinciple).get();
            user.setFirstName(userDto.getNewFirstName());
            user.setLastName(userDto.getNewLastName());
            User savedUser = userRepository.save(user);
            log.info("{ }  data updated successfully", userPrinciple);
            return savedUser;
        } catch (Exception e) {
            log.error("invalid firstname or lastname");
        }
        return null;
    }


    private void authenticate(String username, String password) {
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }


    private TokenInformation getJwtInfo(UserPrincipal userPrincipal) {
        var tokenInfo = new TokenInformation();
        var token = jwtTokenProvider.generateJwtToken(userPrincipal);
        var expiryDate = jwtTokenProvider.getTokenExpiryDate(token);
        var totalLifeTime = expiryDate.getTime() - new Date().getTime();
        var days = TimeUnit.MILLISECONDS.toDays(totalLifeTime);

        tokenInfo.setToken(token);
        tokenInfo.setExpiryTime(days + " Days");
        return tokenInfo;
    }


    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }


    private boolean verifyUser(String token, String email) {
        String subjectUsername = jwtTokenProvider.getSubject(token);
        var emailBySubjectUsername = userRepository.getEmailByUsername(subjectUsername);
        return emailBySubjectUsername.equals(email);
    }

}
