// TST-001: mock investigation pipelines (read-only MCP triage drills).
// Pipeline bodies live under /usr/share/jenkins/ref/mock-pipelines/*.jenkinsfile
// Catalog: testdata/jenkins-compose/FIXTURES.md + mock-pipelines/manifest.json

import java.util.concurrent.TimeUnit
import java.util.logging.Logger
import jenkins.model.Jenkins

def log = Logger.getLogger("init.mcp.mock-fixtures")
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
    [name: "mock-inv-baseline-green",    file: "baseline-green.jenkinsfile",    desc: "Green multi-stage baseline for compare/regression drills"],
    [name: "mock-inv-regression-broken", file: "regression-broken.jenkinsfile", desc: "Same shape as baseline; Test stage fails"],
    [name: "mock-inv-compile-failure",   file: "compile-failure.jenkinsfile",   desc: "Compiler-style failure before tests"],
    [name: "mock-inv-test-failure",      file: "test-failure.jenkinsfile",      desc: "JUnit failures with errors and failures"],
    [name: "mock-inv-unstable",          file: "unstable.jenkinsfile",          desc: "UNSTABLE integration stage; Publish still runs"],
    [name: "mock-inv-nested-stages",     file: "nested-stages.jenkinsfile",     desc: "Failure in nested Contract stage"],
    [name: "mock-inv-parallel-mixed",    file: "parallel-mixed.jenkinsfile",    desc: "Parallel branches; npm-style backend failure"],
    [name: "mock-inv-docker-error",      file: "docker-error.jenkinsfile",      desc: "Docker daemon connection error signature"],
    [name: "mock-inv-oom-killed",        file: "oom-killed.jenkinsfile",        desc: "OOM / exit 137 kill signature"],
    [name: "mock-inv-long-log",          file: "long-log.jenkinsfile",          desc: "~500 log lines for tail/budget testing"],
    [name: "mock-inv-post-failure",      file: "post-failure.jenkinsfile",      desc: "Deploy fails; post always/failure hooks run"],
    [name: "mock-inv-multi-artifact",    file: "multi-artifact.jenkinsfile",    desc: "Multiple archived artifacts + JUnit"],
]

def WorkflowJob
def CpsFlowDefinition
try {
    WorkflowJob = Class.forName("org.jenkinsci.plugins.workflow.job.WorkflowJob")
    CpsFlowDefinition = Class.forName("org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition")
} catch (Throwable t) {
    log.warning("Pipeline plugin unavailable; skipping mock fixtures: ${t.message}")
    return
}

fixtures.each { fx ->
    if (instance.getItem(fx.name) != null) {
        log.info("Fixture job ${fx.name} already exists")
        return
    }
    try {
        def script = loadPipeline(fx.file)
        def job = instance.createProject(WorkflowJob, fx.name)
        job.setDescription("Mock investigation fixture (TST-001): ${fx.desc}")
        def defn = CpsFlowDefinition.getConstructor(String.class, boolean.class)
            .newInstance(script, true)
        job.setDefinition(defn)
        job.save()
        log.info("Created fixture job ${fx.name}")
    } catch (Throwable t) {
        log.warning("Could not create fixture ${fx.name}: ${t.message}")
    }
}

// Schedule one build per fixture; wait collectively up to ~4 minutes (best-effort).
def futures = []
fixtures.each { fx ->
    def item = instance.getItem(fx.name)
    if (item == null) {
        return
    }
    try {
        def future = item.scheduleBuild2(0)
        if (future != null) {
            futures << [name: fx.name, future: future]
        }
    } catch (Throwable t) {
        log.warning("Could not schedule fixture build ${fx.name}: ${t.message}")
    }
}

def deadlineMs = System.currentTimeMillis() + (4 * 60 * 1000)
futures.each { entry ->
    def remaining = deadlineMs - System.currentTimeMillis()
    if (remaining <= 0) {
        log.warning("Fixture build wait budget exhausted before ${entry.name}")
        return
    }
    try {
        entry.future.get(Math.min(remaining, 180_000), TimeUnit.MILLISECONDS)
        log.info("Fixture build finished: ${entry.name}")
    } catch (Throwable t) {
        log.warning("Fixture build ${entry.name} not finished during init: ${t.message}")
    }
}

try {
    new File(instance.getRootDir(), "mcp-mock-fixtures-complete").text = "ok fixtures=${fixtures.size()}\n"
} catch (Throwable t) {
    log.warning("Could not write mcp-mock-fixtures-complete: ${t.message}")
}

instance.save()
