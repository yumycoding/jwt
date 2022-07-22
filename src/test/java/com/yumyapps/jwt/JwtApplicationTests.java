package com.yumyapps.jwt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class JwtApplicationTests {

//    @Test
//    void contextLoads() {
//        System.out.println("test is running");
//    }


    @Test
    void test_log(){
        Assertions.assertEquals(1,1);
    }
}
