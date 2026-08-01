// TST-001: refresh mock pipeline definitions from ref/ on every boot.
// Fixes stale lab volumes after jenkinsfile/plugin updates without requiring down -v.
// Creates missing jobs; updates WorkflowJob definition when the ref file changes.

import java.util.concurrent.TimeUnit
import java.util.logging.Logger
import jenkins.model.Jenkins

def log = Logger.getLogger("init.mcp.resync-fixtures")
def instance = Jenkins.get()
def pipelineRoot = new File("/usr/share/jenkins/ref/mock-pipelines")

def loadPipeline = { String fileName ->
    def f = new File(pipelineRoot, fileName)
    if (!f.isFile()) {
        throw new FileNotFoundException("missing mock pipeline: ${f.absolutePath}")
    }
    return f.text
}

def fixtures = [
    [name: "mock-inv-baseline-green",       file: "baseline-green.jenkinsfile"],
    [name: "mock-inv-regression-broken",    file: "regression-broken.jenkinsfile"],
    [name: "mock-inv-compile-failure",      file: "compile-failure.jenkinsfile"],
    [name: "mock-inv-test-failure",         file: "test-failure.jenkinsfile"],
    [name: "mock-inv-unstable",             file: "unstable.jenkinsfile"],
    [name: "mock-inv-nested-stages",        file: "nested-stages.jenkinsfile"],
    [name: "mock-inv-parallel-mixed",       file: "parallel-mixed.jenkinsfile"],
    [name: "mock-inv-docker-error",         file: "docker-error.jenkinsfile"],
    [name: "mock-inv-oom-killed",           file: "oom-killed.jenkinsfile"],
    [name: "mock-inv-long-log",             file: "long-log.jenkinsfile"],
    [name: "mock-inv-post-failure",         file: "post-failure.jenkinsfile"],
    [name: "mock-inv-multi-artifact",       file: "multi-artifact.jenkinsfile"],
    [name: "mock-inv-build-graph-downstream", file: "build-graph-downstream.jenkinsfile"],
    [name: "mock-inv-build-graph-upstream",   file: "build-graph-upstream.jenkinsfile"],
    [name: "mock-inv-queue-blocked",        file: "queue-blocked.jenkinsfile"],
]

def WorkflowJob
def CpsFlowDefinition
try {
    WorkflowJob = Class.forName("org.jenkinsci.plugins.workflow.job.WorkflowJob")
    CpsFlowDefinition = Class.forName("org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition")
} catch (Throwable t) {
    log.warning("Pipeline plugin unavailable; skipping fixture resync: ${t.message}")
    return
}

def upsertPipeline = { String name, String scriptText ->
    def defn = CpsFlowDefinition.getConstructor(String.class, boolean.class)
        .newInstance(scriptText, true)
    def item = instance.getItem(name)
    if (item == null) {
        item = instance.createProject(WorkflowJob, name)
        item.setDescription("Mock investigation fixture (TST-001 resync)")
        log.info("Created fixture job ${name}")
    }
    item.setDefinition(defn)
    item.save()
}

fixtures.each { fx ->
    try {
        upsertPipeline(fx.name, loadPipeline(fx.file))
    } catch (Throwable t) {
        log.warning("Could not resync fixture ${fx.name}: ${t.message}")
    }
}

// Refresh sample-pipeline seed (02 creates once; this applies junit/wfapi-friendly updates).
def samplePipelineScript = '''
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
try {
    upsertPipeline("sample-pipeline", samplePipelineScript)
    log.info("Resynced sample-pipeline definition")
} catch (Throwable t) {
    log.warning("Could not resync sample-pipeline: ${t.message}")
}

// Schedule one build for graph/queue fixtures when no build exists yet.
["mock-inv-build-graph-downstream", "mock-inv-build-graph-upstream", "mock-inv-queue-blocked"].each { name ->
    def item = instance.getItem(name)
    if (item == null) {
        return
    }
    if (item.getLastBuild() != null) {
        return
    }
    try {
        item.scheduleBuild2(0)
        log.info("Scheduled initial build for ${name}")
    } catch (Throwable t) {
        log.warning("Could not schedule ${name}: ${t.message}")
    }
}

// Best-effort wait for upstream graph build (queue-blocked intentionally not waited).
def upstream = instance.getItem("mock-inv-build-graph-upstream")
if (upstream != null && upstream.getLastBuild() != null) {
    try {
        upstream.getLastBuild().getFuture().get(120, TimeUnit.SECONDS)
        log.info("build-graph-upstream initial build finished")
    } catch (Throwable t) {
        log.warning("build-graph-upstream build wait: ${t.message}")
    }
}

// Re-queue builds so HTTP paths (testReport/wfapi/graph) reflect refreshed definitions.
def rebuildSkip = ["mock-inv-queue-blocked"] as Set
def rebuildFutures = []
fixtures.each { fx ->
    if (rebuildSkip.contains(fx.name)) {
        return
    }
    def item = instance.getItem(fx.name)
    if (item == null) {
        return
    }
    try {
        def future = item.scheduleBuild2(0)
        if (future != null) {
            rebuildFutures << [name: fx.name, future: future]
        }
    } catch (Throwable t) {
        log.warning("Could not queue resync rebuild ${fx.name}: ${t.message}")
    }
}
def sample = instance.getItem("sample-pipeline")
if (sample != null) {
    try {
        def future = sample.scheduleBuild2(0)
        if (future != null) {
            rebuildFutures << [name: "sample-pipeline", future: future]
        }
    } catch (Throwable t) {
        log.warning("Could not queue resync rebuild sample-pipeline: ${t.message}")
    }
}

def rebuildDeadlineMs = System.currentTimeMillis() + (5 * 60 * 1000)
rebuildFutures.each { entry ->
    def remaining = rebuildDeadlineMs - System.currentTimeMillis()
    if (remaining <= 0) {
        log.warning("Resync rebuild wait budget exhausted before ${entry.name}")
        return
    }
    try {
        entry.future.get(Math.min(remaining, 180_000), TimeUnit.MILLISECONDS)
        log.info("Resync rebuild finished: ${entry.name}")
    } catch (Throwable t) {
        log.warning("Resync rebuild ${entry.name} not finished during init: ${t.message}")
    }
}

try {
    new File(instance.getRootDir(), "mcp-fixtures-resync-complete").text = "ok fixtures=${fixtures.size()}\n"
} catch (Throwable t) {
    log.warning("Could not write mcp-fixtures-resync-complete: ${t.message}")
}

instance.save()
