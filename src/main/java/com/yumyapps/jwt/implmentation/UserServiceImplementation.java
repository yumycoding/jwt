package com.yumyapps.jwt.implmentation;


import com.yumyapps.jwt.dto.PasswordUpdateDto;
import com.yumyapps.jwt.enumeration.Role;
import com.yumyapps.jwt.exception.exceptions.*;
import com.yumyapps.jwt.models.User;
import com.yumyapps.jwt.repository.UserRepository;
import com.yumyapps.jwt.security.UserPrincipal;
import com.yumyapps.jwt.service.LoginAttemptService;
import com.yumyapps.jwt.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;

import static com.yumyapps.jwt.constants.Constants.*;
import static com.yumyapps.jwt.enumeration.Role.ROLE_SUPER_ADMIN;
import static org.apache.commons.lang3.StringUtils.EMPTY;

@Slf4j
@Service
@Transactional
@Qualifier("userDetailsService")
public class UserServiceImplementation implements UserService, UserDetailsService {

    private final Logger LOGGER = LoggerFactory.getLogger(getClass());
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttemptService;


    public UserServiceImplementation(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder, LoginAttemptService loginAttemptService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginAttemptService = loginAttemptService;

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username).orElseThrow(() -> new UserNotFoundException("Invalid Username"));
        if (user == null) {
            LOGGER.error("User not Found. The Username is Invalid " + username);
            throw new UsernameNotFoundException("User not Found. The Username is Invalid " + username);
        } else {
            validateLoginAttempts(user, username);
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            userRepository.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            LOGGER.info("User Found " + username);
            return userPrincipal;
        }
    }

    private void validateLoginAttempts(User user, String userName) {
        if (user.isNotLocked()) {
            if (loginAttemptService.hasExceededMaxAttempts(userName)) {
                user.setNotLocked(false);
            } else {
                user.setNotLocked(true);
            }
        } else {
            throw new LockedException("");
            //loginAttemptService.activeUserFromLoginAttemptCache(userName);
        }
    }

    @Override
    public void unlockAccount(String email) {
        var user = userRepository.findUserByEmail(email).orElseThrow(() -> new EmailNotFoundException("Invalid Email"));
        user.setNotLocked(true);
        userRepository.save(user);
        loginAttemptService.activeUserFromLoginAttemptCache(user.getUsername());
    }

    @Override
    public User register(String firstName, String lastName, String username, String email, String password) throws UserNotFoundException, EmailExistException, UsernameExistException {
        User user = new User();

        validateNewUserAndEmail(EMPTY, username, email);
        user.setUserId(generatedUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());

        var encode = encodedPassword(password);
        user.setPassword(encode);
        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(ROLE_SUPER_ADMIN.name());
        user.setAuthorities(ROLE_SUPER_ADMIN.getAuthorities());
        userRepository.save(user);
        LOGGER.info("New User Password {} ", encode);

        return user;
    }

    @Override
    public User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive) throws UserNotFoundException, UsernameExistException, EmailExistException {
        User currentUser = validateUpdateUser(currentUsername, newEmail);
        assert currentUser != null;
        currentUser.setFirstName(newFirstName);
        currentUser.setLastName(newLastName);
        currentUser.setEmail(newEmail);
        currentUser.setActive(isActive);
        currentUser.setNotLocked(isNonLocked);
        currentUser.setRole(getRoleEnumName(role).name());
        currentUser.setAuthorities(getRoleEnumName(role).getAuthorities());
        userRepository.save(currentUser);
        return currentUser;
    }



    @Override
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findUserByUsername(username).orElse(null);
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findUserByEmail(email).orElse(null);
    }


    @Override
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public void deleteUser(String username) {
        User user = userRepository.findUserByUsername(username).orElseThrow(() -> new UserNotFoundException("Invalid Username"));
        user.setActive(false);
        userRepository.save(user);
    }

    @Override
    public void resetPassword(String email, String password) throws UserNotFoundException {

        User userByEmail = userRepository.findUserByEmail(email).orElseThrow(() -> new EmailNotFoundException("Invalid Email"));
        if (null == userByEmail) {
            throw new UserNotFoundException(NO_USER_FOUND_BY_EMAIL + email);
        }

        userByEmail.setPassword(encodedPassword(password));
        userRepository.save(userByEmail);
    }


    @Override
    public boolean updatePassword(UsernamePasswordAuthenticationToken token, PasswordUpdateDto updateDto) {

        if (!updateDto.getNewPassword().equals(updateDto.getMatchingPassword())) {
            log.error("the given password does not match from the user { }", token.getPrincipal());
            throw new PassowrdNotMatchException(PASSWORD_DO_NOT_MATCH);
        }
        if (updateDto.getOldPassword().equals(updateDto.getNewPassword())) {
            log.error("old password and new passwords are same from the user { }", token.getPrincipal());
            throw new OldPasswordDenialException(OLD_PASSWORD_DENIED);
        }
        try {
            var result = verifyPassword(token.getPrincipal().toString(), updateDto.getOldPassword());
            if (result) {
                var user = findUserByUsername(token.getPrincipal().toString());
                user.setPassword(passwordEncoder.encode(updateDto.getNewPassword()));
                userRepository.save(user);
                log.info("{} has changed the password successfully", token.getPrincipal().toString());
                return true;
            }
        } catch (Exception e) {
            log.error(e.getStackTrace().toString());
        }
        log.error("invalid password, old password cannot be verified from the user { }", token.getPrincipal());
        return false;
    }

    @Override
    public String findEmailBySubjectUsername(String username) {
        return userRepository.getEmailByUsername(username);
    }

    @Override
    public String getPasswordByUserName(String username) {
        return userRepository.getPasswordByUsername(username);
    }

    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase());
    }


    private String encodedPassword(String password) {
        return passwordEncoder.encode(password);
    }


    private boolean verifyPassword(String username, String oldPassword) {
        String passwordByUsername = getPasswordByUserName(username);
        return passwordEncoder.matches(oldPassword, passwordByUsername);

    }


    private String generatedUserId() {
        return RandomStringUtils.randomNumeric(10);
    }


    private User validateUpdateUser(String currentUserName, String email) {

        if (StringUtils.isNotBlank(currentUserName) && StringUtils.isNotBlank(email)) {

            User currentUser = findUserByUsername(currentUserName);
            User userByNewEmail = findUserByEmail(email);

            if (currentUser == null) {
                throw new UserNotFoundException(NO_USER_FOUND_BY_USERNAME + currentUserName);
            }
            if (userByNewEmail != null) {
                throw new EmailExistException(EMAIL_ALREADY_EXISTS);
            }
            return currentUser;
        } else {
            return null;
        }
    }

    private User validateNewUserAndEmail(String currentUserName, String newUserName, String emailAddress) throws UserNotFoundException, UsernameExistException, EmailExistException {

        User userByNewUsername = findUserByUsername(newUserName);
        User userByNewEmail = findUserByEmail(emailAddress);

        if (StringUtils.isNotBlank(currentUserName)) {
            User currentUser = findUserByUsername(currentUserName);
            if (currentUser == null) {
                throw new UserNotFoundException(NO_USER_FOUND_BY_USERNAME + currentUserName);
            }
            if (userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())) {
                throw new UsernameExistException(USERNAME_ALREADY_EXISTS);
            }
            if (userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())) {
                throw new EmailExistException(EMAIL_ALREADY_EXISTS);
            }
            return currentUser;
        } else {
            if (userByNewUsername != null) {
                throw new UsernameExistException(USERNAME_ALREADY_EXISTS);
            }
            if (userByNewEmail != null) {
                throw new EmailExistException(EMAIL_ALREADY_EXISTS);
            }
            return null;
        }

    }


}