FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY libs ./libs
COPY src ./src
RUN mvn clean package

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/pqc-signer-1.0-SNAPSHOT.jar ./pqc-signer.jar
EXPOSE 8081
CMD ["java", "-jar", "pqc-signer.jar"]
