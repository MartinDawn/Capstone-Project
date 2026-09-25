FROM maven:3.9.6-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre@sha256:bd25c61779663bc2df8ced059f1cc114fafc073afe16125c13fcc3a37fecd845
WORKDIR /app
COPY --from=builder /app/target/tpp-java-1.0-SNAPSHOT.jar app.jar
EXPOSE 6001
ENTRYPOINT ["java", "-jar", "app.jar"]
