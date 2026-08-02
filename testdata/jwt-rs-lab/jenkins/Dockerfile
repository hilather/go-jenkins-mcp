# Disposable Jenkins LTS + jwt-auth-filter for free RS lab.
# NOT for production. Lab credentials only.
FROM jenkins/jenkins:lts-jdk17

USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/*

USER jenkins

COPY --chown=jenkins:jenkins plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY --chown=jenkins:jenkins init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/

ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
