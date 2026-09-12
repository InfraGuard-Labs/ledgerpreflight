FROM eclipse-temurin:17-jre-jammy@sha256:ec72ba5962b45ae4e7f96bfb5ebf6eeb34a488b967f937c8e14f0aaec688954f AS java-runtime
FROM gradle:8.12.1-jdk17@sha256:deb3ed64f189e9b326e4147de66335286eea9f8b6677e53514af62370cbf7a4a AS gradle-toolchain
FROM eclipse-temurin:17-jdk-jammy@sha256:ef4374b4b6b9d813dd3f5b593a35ec9a820cfb64a55994798147cc73435a0208 AS build
COPY --from=gradle-toolchain /opt/gradle /opt/gradle
COPY --from=java-runtime /opt/java/openjdk /opt/ledgerpreflight-jre
ENV PATH="/opt/gradle/bin:${PATH}" GRADLE_USER_HOME=/home/gradle/.gradle
WORKDIR /workspace
COPY . .
ARG GRADLE_CACHE_ID=ledgerpreflight-build
RUN --mount=type=cache,id=${GRADLE_CACHE_ID},target=/home/gradle/.gradle gradle --no-daemon clean test jar syntheticReplay benchmark sbom
FROM java-runtime AS runtime
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 ledger && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin ledger
WORKDIR /app
COPY --from=build /workspace/build/libs/ledger-preflight-0.1.0.jar /app/ledger-preflight.jar
USER 10001:10001
ENTRYPOINT ["java", "-Xmx512m", "-jar", "/app/ledger-preflight.jar"]
