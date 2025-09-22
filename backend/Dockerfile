# Stage 1: Build the custom JRE using a full JDK
# We use a specific arch-tagged image to ensure the correct JDK is used for the target platform.
FROM amazoncorretto:25.0.0-alpine3.22@sha256:807ea3c4000a052986cd1e7097a883f9cd7a6e527f73841f462e3d04851b8835 AS jre-builder

# Set the working directory
WORKDIR /opt/build

# Install binutils which provides the 'objcopy' tool needed for the '--strip-debug' option in jlink.
RUN apk add --no-cache binutils

# Copy the application JAR into the builder stage
COPY target/app.jar .

# 1. Analyze the JAR to find the required Java modules
# 2. Build a minimal, custom Java runtime with those modules
# 3. Ensure the binaries in the new JRE are executable
RUN jdeps \
        --ignore-missing-deps \
        --print-module-deps \
        app.jar > jre-deps.info && \
    jlink \
        --add-modules $(cat jre-deps.info),java.desktop \
        --strip-debug \
        --no-man-pages \
        --no-header-files \
        --compress=2 \
        --output /opt/jre && \
    chmod +x /opt/jre/bin/*


# Stage 2: Build the final, minimal application image
FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

# Create a non-root user and group for security
RUN addgroup -S tekmetric && adduser -S tekmetric -G tekmetric

# Set the working directory
WORKDIR /app

# Copy the custom JRE from the jre-builder stage
COPY --from=jre-builder --chown=tekmetric:tekmetric /opt/jre /opt/jre
# Copy the application JAR from the jre-builder stage
COPY --from=jre-builder --chown=tekmetric:tekmetric /opt/build/app.jar app.jar

# Configure the environment to use the custom JRE
ENV JAVA_HOME=/opt/jre
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# Switch to the non-root user
USER tekmetric

# Expose the application port
EXPOSE 8080

# Set the entrypoint to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]

