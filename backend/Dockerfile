FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

# Create a non-root user for security
RUN addgroup -S tekmetric && adduser -S tekmetric -G tekmetric

WORKDIR /app

# Copy the custom JRE and application JAR, setting ownership to the non-root user
COPY --chown=tekmetric:tekmetric custom-jre /opt/jre
COPY --chown=tekmetric:tekmetric target/app.jar app.jar

# Configure the environment to use the custom JRE
ENV JAVA_HOME=/opt/jre
ENV PATH="${JAVA_HOME}/bin:${PATH}"
RUN chmod +x /opt/jre/bin/*
# Switch to the non-root user
USER tekmetric

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]

