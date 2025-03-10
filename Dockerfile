FROM maven:3.9.5-openjdk-21 AS build
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean install -DskipTests=false

FROM openjdk:21-jdk
WORKDIR /app

COPY --from=build /app/target/fos-auth-0.0.1.jar fos-auth.jar

EXPOSE 9000
ENTRYPOINT ["java", "-jar", "fos-auth.jar"]
