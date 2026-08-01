// TST-001: seed freestyle + Pipeline + JUnit sample; trigger one build each.
// Runs after plugins load. Failures are logged; smoke script may re-trigger builds.

import java.util.concurrent.TimeUnit
import java.util.logging.Logger
import jenkins.model.Jenkins
import hudson.model.FreeStyleProject
import hudson.tasks.Shell
import hudson.tasks.ArtifactArchiver

def log = Logger.getLogger("init.mcp.jobs")
def instance = Jenkins.get()

def freeName = "sample-freestyle"
if (instance.getItem(freeName) == null) {
    def job = instance.createProject(FreeStyleProject, freeName)
    job.setDescription("Disposable freestyle job for go-jenkins-mcp live smoke (TST-001)")
    job.buildersList.add(new Shell('''#!/bin/bash
set -euo pipefail
echo "hello from sample-freestyle"
mkdir -p target/surefire-reports out
cat > target/surefire-reports/TEST-Sample.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="Sample" tests="2" failures="1" errors="0" skipped="0" time="0.1">
  <testcase classname="com.example.Sample" name="testPass" time="0.01"/>
  <testcase classname="com.example.Sample" name="testFail" time="0.01">
    <failure message="expected true">stack</failure>
  </testcase>
</testsuite>
EOF
echo "artifact content" > out/hello.txt
'''))
    try {
        def junitCls = Class.forName("hudson.tasks.junit.JUnitResultArchiver")
        def junit = junitCls.getConstructor(String.class).newInstance("**/TEST-*.xml")
        job.publishersList.add(junit)
    } catch (Throwable t) {
        log.warning("JUnit publisher unavailable: ${t.message}")
    }
    job.publishersList.add(new ArtifactArchiver("out/**"))
    job.save()
    log.info("Created job ${freeName}")
} else {
    log.info("Job ${freeName} already exists")
}

def pipeName = "sample-pipeline"
if (instance.getItem(pipeName) == null) {
    try {
        def WorkflowJob = Class.forName("org.jenkinsci.plugins.workflow.job.WorkflowJob")
        def CpsFlowDefinition = Class.forName("org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition")
        def job = instance.createProject(WorkflowJob, pipeName)
        def script = '''
pipeline {
  agent any
  stages {
    stage("Build") {
      steps {
        echo "hello from sample-pipeline"
        sh """
          set -euo pipefail
          mkdir -p target/surefire-reports out
          echo "pipeline log line"
          cat > target/surefire-reports/TEST-SamplePipeline.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="SamplePipeline" tests="1" failures="0" errors="0" skipped="0" time="0.01">
  <testcase classname="com.example.Pipeline" name="testSmoke" time="0.01"/>
</testsuite>
EOF
          echo "pipeline artifact" > out/pipeline.txt
        """
        junit testResults: 'target/surefire-reports/TEST-*.xml', allowEmptyResults: false
        archiveArtifacts artifacts: 'out/**', fingerprint: true
      }
    }
  }
}
'''
        def defn = CpsFlowDefinition.getConstructor(String.class, boolean.class)
            .newInstance(script, true)
        job.setDefinition(defn)
        job.save()
        log.info("Created job ${pipeName}")
    } catch (Throwable t) {
        log.warning("Pipeline job not created (plugin missing?): ${t.message}")
    }
} else {
    log.info("Job ${pipeName} already exists")
}

// Trigger builds so get-build / progressive log have data. Best-effort wait.
["sample-freestyle", "sample-pipeline"].each { name ->
    def item = instance.getItem(name)
    if (item == null) {
        return
    }
    try {
        def future = item.scheduleBuild2(0)
        if (future != null) {
            future.get(180, TimeUnit.SECONDS)
            log.info("Initial build finished for ${name}")
        }
    } catch (Throwable t) {
        log.warning("Initial build for ${name} did not complete during init: ${t.message}")
    }
}

// Marker for host-side wait (token file is the auth gate; this marks job seed done).
try {
    new File(instance.getRootDir(), "mcp-init-complete").text = "ok\n"
} catch (Throwable t) {
    log.warning("Could not write mcp-init-complete: ${t.message}")
}

instance.save()
