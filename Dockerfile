FROM eclipse-temurin:17-jre-jammy@sha256:ec72ba5962b45ae4e7f96bfb5ebf6eeb34a488b967f937c8e14f0aaec688954f AS java-runtime
# Pin the upstream security patch while the distribution image catches up.
ENV JAVA_VERSION=jdk-17.0.20.1+1
RUN set -eu; \
    test "$(dpkg --print-architecture)" = amd64; \
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --max-time 300 \
        'https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jre_x64_linux_hotspot_17.0.20.1_1.tar.gz' \
        --output /tmp/ledgerpreflight-jre.tar.gz; \
    echo '0b2b640e3046b64c8ec504de0ab9d91bb5610182bda21fad454681ce54d45a62  /tmp/ledgerpreflight-jre.tar.gz' | sha256sum --check -; \
    rm -rf /opt/java/openjdk; \
    mkdir -p /opt/java/openjdk; \
    tar --extract --gzip --file /tmp/ledgerpreflight-jre.tar.gz \
        --directory /opt/java/openjdk --strip-components 1 --no-same-owner; \
    rm -f /tmp/ledgerpreflight-jre.tar.gz; \
    /opt/java/openjdk/bin/java -version
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
ENTRYPOINT ["java", "-Xmx256m", "-jar", "/app/ledger-preflight.jar"]
