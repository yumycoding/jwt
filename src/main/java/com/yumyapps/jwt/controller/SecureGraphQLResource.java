package com.yumyapps.jwt.controller;

import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

@Controller
public class SecureGraphQLResource {

    @QueryMapping
    public String message(@Argument Long value) {
        return "GraphQl " + value;
    }

}
