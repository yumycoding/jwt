FROM gradle:7.4 AS build
COPY --chown=gradle:gradle . /home/gradle
WORKDIR /home/gradle
RUN gradle build -x test --no-daemon
FROM openjdk:11
EXPOSE 8200
COPY --from=build /home/gradle/build/libs/jwt-1.0.jar /jwt.jar
CMD ["java", "-jar", "/jwt.jar"]







#FROM openjdk:11
#EXPOSE 8200
#COPY build/libs/jwt-1.0.jar /jwt.jar
#CMD ["java", "-jar", "/jwt.jar"]