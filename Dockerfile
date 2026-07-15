FROM maven:3.9.9-eclipse-temurin-17 AS build

WORKDIR /workspace

COPY pom.xml .
COPY src ./src

RUN mvn -B -DskipTests package && cp target/*SNAPSHOT.jar target/app.jar

FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

ENV APP_PORT=8081

COPY --from=build /workspace/target/app.jar /app/app.jar

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
