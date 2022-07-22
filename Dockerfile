FROM openjdk:11
EXPOSE 8200
COPY build/libs/jwt-1.0.jar /jwt.jar
CMD ["java", "-jar", "/jwt.jar"]