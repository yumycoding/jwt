#FROM maven:3.6.1-openjdk:11 AS MAVEN_BUILD
#EXPOSE 8200
#ARG JAR_FILE=/build/lib/*.jar
#COPY ${JAR_FILE} jwt-1.0.jar
#
#
#ENTRYPOINT ["java", "-jar", "/jwt-1.0.jar"]
