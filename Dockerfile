
FROM openjdk:21-jdk
WORKDIR /app
COPY target/fos-auth-0.0.1-SNAPSHOT.jar /app/fos-auth.jar
EXPOSE 9000
ENTRYPOINT ["java", "-jar", "/app/fos-auth.jar"]