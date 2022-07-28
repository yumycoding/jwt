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
import java.util.ArrayList;
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
                log.info("{ } account is locked after multiply login attempts", userName);
            } else {
                user.setNotLocked(true);
            }
        } else {
            throw new LockedException("Account is temporary locked, please contact admin");
            //loginAttemptService.activeUserFromLoginAttemptCache(userName);
        }
    }

    @Override
    public void unlockAccount(String email) {

        var user = userRepository.findUserByEmail(email).orElseThrow(() -> new EmailNotFoundException("Invalid Email"));
        try {
            user.setNotLocked(true);
            userRepository.save(user);
            loginAttemptService.activeUserFromLoginAttemptCache(user.getUsername());
            log.info("{ } account is unlocked successfully", user.getUsername());
        } catch (Exception e) {
            log.error("Invalid Email or System Error", e.getMessage());

        }
    }

    @Override
    public User register(String firstName, String lastName, String username, String email, String password) throws UserNotFoundException, EmailExistException, UsernameExistException {
        User user = new User();

        validateNewUserAndEmail(EMPTY, username, email);
        try {
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
            log.info("new user with username { } is registered successfully", user.getUsername());

        } catch (Exception e) {
            log.error("Error Wile Registering user", e.getMessage());
        }
        return user;
    }

    @Override // function not in use
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
        List<User> userList = new ArrayList<>();
        try {
            userList = userRepository.findAll();
            log.info("returning all users");
        } catch (Exception e) {
            log.error("Error wile generating user list", e.getMessage());
        }
        return userList;
    }

    @Override
    public User findUserByUsername(String username) {
        var user = new User();
        try {
            user = userRepository.findUserByUsername(username).orElse(null);
        } catch (Exception e) {
            log.error("Error while fetching user with username", e.getMessage());
        }
        return user;
    }

    @Override
    public User findUserByEmail(String email) {
        var user = new User();
        try {
            user = userRepository.findUserByEmail(email).orElse(null);
        } catch (Exception e) {
            log.error("Error while fetching user with email", e.getMessage());
        }
        return user;


    }


    @Override // method is not in use
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    @Override // user soft delete method
    public void deleteUser(String username) {
        User user = userRepository.findUserByUsername(username).orElseThrow(() -> new UserNotFoundException("Invalid Username"));
        try {
            user.setActive(false);
            userRepository.save(user);
        } catch (Exception e) {
            log.error("Error While deleting user", e.getMessage());
        }
    }

    @Override // method is not in use. 2-factor authentication may implement
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
        String email = null;
        try {
            email = userRepository.getEmailByUsername(username);
        } catch (Exception e) {
            log.error("Subject email Error", e.getMessage());
        }
        return email;
    }

    @Override
    public String getPasswordByUserName(String username) {
        String userPassword = null;
        try {
            userPassword = userRepository.getPasswordByUsername(username);
        } catch (Exception e) {
            log.error("Password Error", e.getMessage());
        }
        return userPassword;
    }

    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase());
    }


    private String encodedPassword(String password) {
        String newEncodedPassword;

        if (StringUtils.isNotBlank(password)) {
            newEncodedPassword = passwordEncoder.encode(password);
            return newEncodedPassword;
        } else {
            throw new NullPointerException("Password is Empty or Null");
        }
    }


    private boolean verifyPassword(String username, String oldPassword) {
        boolean result = false;
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(oldPassword)) {
            String passwordByUsername = getPasswordByUserName(username);
            result = passwordEncoder.matches(oldPassword, passwordByUsername);
        }
        return result;
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

    private User validateNewUserAndEmail(String currentUserName, String newUserName, String emailAddress) throws
            UserNotFoundException, UsernameExistException, EmailExistException {

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
