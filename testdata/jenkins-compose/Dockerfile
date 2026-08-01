# Disposable Jenkins LTS for TST-001 live smoke tests.
# NOT for production. Ephemeral credentials only; never bake real tokens.
FROM jenkins/jenkins:lts-jdk17

USER root
# curl for container healthcheck (host-side wait is primary)
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/*

USER jenkins

COPY --chown=jenkins:jenkins plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY --chown=jenkins:jenkins init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/

# Skip setup wizard; security is configured by init groovy.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
