# SolarNetwork Developer OAuth Server

This project is a bare-bones OAuth Authorization Server designed to support development of OAuth
client applications.

# Building

The build is managed by Gradle, and requires a Java Development Kit version 17+ to build (and run).

```sh
# Unix-like OS
./gradlew build

# Windows
./gradlew.bat build
```

This will build an executable JAR in the `build/libs` directory, named like 
`solarnet-dev-auth-server-X.jar` where `X` is a version number.

# Running

To run the app:

```sh
java -jar build/libs/solarnet-dev-auth-server-1.0.0.jar
```

# Configuration

Create an `application.yml` file in your launch working directory. See the 
[default configuration](./tree/main/src/main/resources/application.yml) for
reference. For example:

```yml
app:
  oauth:
    scopes:
      - "good"
      - "times"
    client-id: "dev-client"
    client-secret: "{noop}dev-client-secret"
    keystore:
      path: "var/keystore"
      password: "Secret.123"
      alias: "auth-server"
```