package com.yumyapps.jwt.service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutionException;

import static java.util.concurrent.TimeUnit.MINUTES;

@Slf4j
@Service
public class LoginAttemptService {

    private static final int MAXIMUM_NUMBER_OF_ATTEMPTS = 5;
    private static final int ATTEMPTS_INCREMENT = 1;
    private LoadingCache<String, Integer> loginAttemptCache;

    public LoginAttemptService() {
        super();
        loginAttemptCache = CacheBuilder.newBuilder().expireAfterWrite(5, MINUTES)
                .maximumSize(100).build(new CacheLoader<>() {
                    public Integer load(String key) {
                        return 0;
                    }
                });
    }

    public void activeUserFromLoginAttemptCache(String username) {
        loginAttemptCache.invalidate(username);
    }

    public void addUserToLoginAttemptCache(String username) {
        int attempts = 0;
//        System.out.println(username);
        try {
            attempts = ATTEMPTS_INCREMENT + loginAttemptCache.get(username);
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        loginAttemptCache.put(username, attempts);
        try {


            System.out.println("total attempts of " + username + " : " + loginAttemptCache.get(username));
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
    }

    public boolean hasExceededMaxAttempts(String username) {
        try {

            return loginAttemptCache.get(username) >= MAXIMUM_NUMBER_OF_ATTEMPTS;
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return false;
    }

}


