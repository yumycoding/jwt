//package com.yumyapps.jwt.config;
//
//
//import graphql.scalars.ExtendedScalars;
//import graphql.scalars.java.JavaPrimitives;
//import graphql.schema.idl.RuntimeWiring;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.graphql.execution.RuntimeWiringConfigurer;
//
//@Configuration
//public class GraphQLScalarConfig implements RuntimeWiringConfigurer {
//
//    @Override
//    public void configure(RuntimeWiring.Builder builder) {
//        builder.scalar(JavaPrimitives.GraphQLLong)
//                .scalar(ExtendedScalars.Date)
//                .build();
//    }
//}
