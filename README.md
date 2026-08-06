# hiemdall

Centralised authentication & authorization server. Google OAuth login,
token lifecycle, session JWT issuance.

Single-project Gradle build. Java 21, Spring Boot 3. Versions in
`gradle/libs.versions.toml`.


http://localhost:8082/auth/google/start?app=kkt

## Build

```bash
./gradlew build          # compile + test
./gradlew bootJar        # runnable fat JAR → build/libs/hiemdall-<version>.jar
./gradlew format         # Spotless (Google Java Format AOSP)
```

## Run

```bash
./gradlew bootRun
```

Default port `8082` (see `Dockerfile` healthcheck).
