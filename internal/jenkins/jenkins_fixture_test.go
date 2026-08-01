package jenkins

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// jenkinsFixture is a minimal Jenkins-like HTTP server for contract tests (FND-003).
type jenkinsFixture struct {
	wfapiLogJSON  map[string]string // key: jobPath/build/nodeID → log JSON (PIPE-002)
	artifactBytes map[string][]byte // key: jobPath/build/relPath → body (ART-001)
	artifactHits  atomic.Int32      // download hits (list must not increment)

	Server *httptest.Server

	mu              sync.Mutex
	bytesServed     atomic.Int64
	progressive     map[string]string // key: jobPath/build -> full log text
	progressiveSize map[string]int    // key: jobPath/build -> synthetic log length (PERF-001)
	jobsJSON        string
	jobJSON         map[string]string
	buildJSON       map[string]string
	queueJSON       map[int]string
	runningJSON     string
	queueAPIJSON    string
	stopCalls       atomic.Int32
	startCalls      atomic.Int32
	cancelCalls     atomic.Int32
	// cancelStatus, when non-zero, overrides the HTTP status for /queue/cancelItem.
	// cancelMissingIDs maps queue id → true to force 404 on cancel for that id.
	cancelStatus     int
	cancelMissingIDs map[int]bool
	// crumbJSON, when non-empty, is returned from /crumbIssuer/api/json (else 404).
	crumbJSON string
	// lastCancelCrumb records the Jenkins-Crumb (or configured field) header on cancel POST.
	lastCancelCrumb string
	authUser        string
	authToken       string
	requireAuth     bool

	// JEN-001 / PIPE-001 / TEST-001 capability and feature fixtures
	jenkinsVersion    string            // X-Jenkins header value
	pluginManagerJSON string            // empty ⇒ 404; "deny" ⇒ 403
	descriptors       map[string]int    // path suffix → status (200 body "{}")
	wfapiJSON         map[string]string // key: jobPath/build → describe JSON
	wfapiNodeJSON     map[string]string // key: jobPath/build/nodeID → node describe
	testReportJSON    map[string]string // key: jobPath/build → testReport JSON; missing ⇒ 404

	// HEALTH-002 / DIAG-007 root mode flags (merged into /api/json payload).
	quietingDown bool
	rootMode     string // e.g. "NORMAL"
	numExecutors int    // controller executors; 0 ⇒ omit
}

func newJenkinsFixture() *jenkinsFixture {
	f := &jenkinsFixture{
		progressive:      make(map[string]string),
		progressiveSize:  make(map[string]int),
		jobJSON:          make(map[string]string),
		buildJSON:        make(map[string]string),
		queueJSON:        make(map[int]string),
		cancelMissingIDs: make(map[int]bool),
		requireAuth:      true,
		authUser:         "tester",
		authToken:        "secret-token-value",
		runningJSON:      `{"computer":[]}`,
		queueAPIJSON:     `{"items":[]}`,
		jenkinsVersion:   "2.462.3",
		descriptors:      make(map[string]int),
		wfapiJSON:        make(map[string]string),
		wfapiNodeJSON:    make(map[string]string),
		wfapiLogJSON:     make(map[string]string),
		artifactBytes:    make(map[string][]byte),
		testReportJSON:   make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.handle)
	f.Server = httptest.NewServer(mux)
	return f
}

func (f *jenkinsFixture) close() { f.Server.Close() }

func (f *jenkinsFixture) opts() *Client {
	return &Client{
		URL:        f.Server.URL,
		Auth:       f.authUser + ":" + f.authToken,
		User:       f.authUser,
		Token:      f.authToken,
		Client:     f.Server.Client(),
		LogsClient: f.Server.Client(),
	}
}

func (f *jenkinsFixture) setLog(jobPath string, build int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build)
	f.progressive[key] = body
	delete(f.progressiveSize, key)
}

// setLogSize registers a synthetic progressive log of exactly size bytes without
// materializing the full body (PERF-001 large baselines). Bytes are a repeating
// alphabet pattern. The handler still *offers* the full remainder (Jenkins-like);
// post-LOG-001 clients LimitReader and close early so only a bounded prefix is
// actually written/read into application buffers.
func (f *jenkinsFixture) setLogSize(jobPath string, build int, size int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build)
	f.progressiveSize[key] = size
	delete(f.progressive, key)
}

func (f *jenkinsFixture) handle(w http.ResponseWriter, r *http.Request) {
	if f.requireAuth {
		u, p, ok := r.BasicAuth()
		if !ok || u != f.authUser || p != f.authToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("auth required"))
			return
		}
	}

	// Decode path segments so BuildJobPath PathEscape (spaces, etc.) matches fixture keys.
	path := r.URL.Path
	if dec, err := url.PathUnescape(path); err == nil {
		path = dec
	}
	// Capability probes and all API responses advertise X-Jenkins (JEN-001).
	if f.jenkinsVersion != "" {
		w.Header().Set("X-Jenkins", f.jenkinsVersion)
	}

	switch {
	case path == "/api/json" || path == "/api/json/":
		f.writeJSON(w, f.jobsPayload())
	case path == "/pluginManager/api/json" || strings.HasPrefix(path, "/pluginManager/api/json"):
		f.handlePluginManager(w)
	case strings.HasPrefix(path, "/descriptorByName/"):
		f.handleDescriptor(w, path)
	case strings.Contains(path, "/artifact/"):
		// ART-001: /job/.../<build>/artifact/<relPath>
		f.handleArtifact(w, path)
	case strings.Contains(path, "/wfapi/describe") || strings.Contains(path, "/wfapi/"):
		f.handleWFAPI(w, path)
	case strings.Contains(path, "/testReport/api/json") || strings.HasSuffix(path, "/testReport/api/json"):
		f.handleTestReport(w, path)
	case strings.HasSuffix(path, "/api/json") && strings.Contains(path, "/job/"):
		f.handleJobOrBuildAPI(w, r, path)
	case strings.Contains(path, "/logText/progressiveText"):
		f.handleProgressive(w, r, path)
	case path == "/queue/api/json" || strings.HasPrefix(path, "/queue/api/json"):
		f.writeJSON(w, f.queueAPIJSON)
	case strings.HasPrefix(path, "/queue/item/") && strings.HasSuffix(path, "/api/json"):
		f.handleQueueItem(w, path)
	case path == "/computer/api/json" || strings.HasPrefix(path, "/computer/api/json"):
		f.writeJSON(w, f.runningJSON)
	case strings.HasSuffix(path, "/stop"):
		f.stopCalls.Add(1)
		w.WriteHeader(http.StatusFound)
	case path == "/queue/cancelItem" || strings.HasPrefix(path, "/queue/cancelItem"):
		f.handleCancelItem(w, r)
	case strings.Contains(path, "/buildWithParameters") || strings.HasSuffix(path, "/build"):
		f.startCalls.Add(1)
		w.Header().Set("Location", f.Server.URL+"/queue/item/42/")
		w.WriteHeader(http.StatusCreated)
	case path == "/crumbIssuer/api/json":
		f.mu.Lock()
		crumb := f.crumbJSON
		f.mu.Unlock()
		if crumb == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.writeJSON(w, crumb)
	default:
		// tree/depth variants on root jobs list sometimes include query only
		if path == "/" {
			f.writeJSON(w, f.jobsPayload())
			return
		}
		http.NotFound(w, r)
	}
}

func (f *jenkinsFixture) handlePluginManager(w http.ResponseWriter) {
	f.mu.Lock()
	body := f.pluginManagerJSON
	f.mu.Unlock()
	switch body {
	case "":
		http.NotFound(w, nil)
	case "deny":
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	default:
		f.writeJSON(w, body)
	}
}

func (f *jenkinsFixture) handleDescriptor(w http.ResponseWriter, path string) {
	f.mu.Lock()
	status, ok := f.descriptors[path]
	f.mu.Unlock()
	if !ok {
		// Also match without trailing bits
		http.NotFound(w, nil)
		return
	}
	if status == http.StatusOK {
		f.writeJSON(w, `{}`)
		return
	}
	w.WriteHeader(status)
}

func (f *jenkinsFixture) handleWFAPI(w http.ResponseWriter, path string) {
	// /job/demo/7/wfapi/describe
	// /job/demo/7/execution/node/6/wfapi/describe
	// /job/demo/7/execution/node/6/wfapi/log  (PIPE-002 stage log)
	if strings.Contains(path, "/execution/node/") {
		// .../execution/node/<id>/wfapi/{describe|log}
		idx := strings.Index(path, "/execution/node/")
		prefix := strings.Trim(path[:idx], "/")
		rest := path[idx+len("/execution/node/"):]
		nodeID := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			nodeID = rest[:i]
		}
		key := prefix + "/" + nodeID
		// Stage/node log (PIPE-002): prefer wfapiLogJSON for /wfapi/log.
		if strings.Contains(path, "/wfapi/log") {
			f.mu.Lock()
			body, ok := f.wfapiLogJSON[key]
			f.mu.Unlock()
			if !ok {
				http.NotFound(w, nil)
				return
			}
			f.writeJSON(w, body)
			return
		}
		f.mu.Lock()
		body, ok := f.wfapiNodeJSON[key]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, nil)
			return
		}
		f.writeJSON(w, body)
		return
	}
	// run-level describe
	idx := strings.Index(path, "/wfapi/")
	if idx < 0 {
		http.NotFound(w, nil)
		return
	}
	prefix := strings.Trim(path[:idx], "/")
	f.mu.Lock()
	body, ok := f.wfapiJSON[prefix]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	f.writeJSON(w, body)
}

func (f *jenkinsFixture) handleTestReport(w http.ResponseWriter, path string) {
	// /job/demo/7/testReport/api/json
	idx := strings.Index(path, "/testReport/")
	if idx < 0 {
		http.NotFound(w, nil)
		return
	}
	prefix := strings.Trim(path[:idx], "/")
	f.mu.Lock()
	body, ok := f.testReportJSON[prefix]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	f.writeJSON(w, body)
}

// setPlugins installs a pluginManager payload (shortName list with active=true).
func (f *jenkinsFixture) setPlugins(active ...string) {
	type p struct {
		ShortName string `json:"shortName"`
		Version   string `json:"version"`
		Active    bool   `json:"active"`
		Enabled   bool   `json:"enabled"`
	}
	list := make([]p, 0, len(active))
	for _, name := range active {
		list = append(list, p{ShortName: name, Version: "1.0", Active: true, Enabled: true})
	}
	b, _ := json.Marshal(map[string]any{"plugins": list})
	f.mu.Lock()
	f.pluginManagerJSON = string(b)
	f.mu.Unlock()
}

func (f *jenkinsFixture) setDescriptor(path string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.descriptors[path] = status
}

func (f *jenkinsFixture) setWFAPI(jobPath string, build int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build)
	f.wfapiJSON[key] = body
}

func (f *jenkinsFixture) setWFAPINode(jobPath string, build int, nodeID, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build) + "/" + nodeID
	f.wfapiNodeJSON[key] = body
}

func (f *jenkinsFixture) setTestReport(jobPath string, build int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build)
	f.testReportJSON[key] = body
}

func (f *jenkinsFixture) jobsPayload() string {
	// Merge controller mode flags for HEALTH-002 / DIAG-007 tree probes.
	// When jobsJSON is custom, still inject quietingDown/mode if absent.
	base := f.jobsJSON
	if base == "" {
		base = `{"jobs":[{"name":"demo","fullName":"demo","url":"http://jenkins/job/demo/","color":"blue","buildable":true,"description":"demo job","_class":"hudson.model.FreeStyleProject","lastBuild":{"number":7,"url":"http://jenkins/job/demo/7/"}}]}`
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(base), &m); err != nil {
		return base
	}
	m["quietingDown"] = f.quietingDown
	if f.rootMode != "" {
		m["mode"] = f.rootMode
	} else if _, ok := m["mode"]; !ok {
		m["mode"] = "NORMAL"
	}
	if f.numExecutors > 0 {
		m["numExecutors"] = f.numExecutors
	} else if _, ok := m["numExecutors"]; !ok {
		m["numExecutors"] = 2
	}
	b, err := json.Marshal(m)
	if err != nil {
		return base
	}
	return string(b)
}

// setNestedJobsFixture installs a multi-folder multibranch/matrix tree for JEN-002.
func (f *jenkinsFixture) setNestedJobsFixture() {
	// Root listing
	f.jobsJSON = `{
		"jobs": [
			{
				"name": "team",
				"fullName": "team",
				"_class": "com.cloudbees.hudson.plugins.folder.Folder",
				"url": "http://jenkins/job/team/",
				"color": "blue",
				"buildable": false,
				"description": "team folder"
			},
			{
				"name": "top-level",
				"fullName": "top-level",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/top-level/",
				"color": "blue",
				"buildable": true,
				"lastBuild": {"number": 1, "result": "SUCCESS", "building": false, "timestamp": 1700000000000, "duration": 100}
			}
		]
	}`
	// team folder children
	f.jobJSON["job/team"] = `{
		"name": "team",
		"fullName": "team",
		"_class": "com.cloudbees.hudson.plugins.folder.Folder",
		"jobs": [
			{
				"name": "app with spaces",
				"fullName": "team/app with spaces",
				"_class": "com.cloudbees.hudson.plugins.folder.Folder",
				"url": "http://jenkins/job/team/job/app%20with%20spaces/",
				"color": "blue",
				"buildable": false
			},
			{
				"name": "mb",
				"fullName": "team/mb",
				"_class": "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject",
				"url": "http://jenkins/job/team/job/mb/",
				"color": "blue",
				"buildable": false
			},
			{
				"name": "matrix-parent",
				"fullName": "team/matrix-parent",
				"_class": "hudson.matrix.MatrixProject",
				"url": "http://jenkins/job/team/job/matrix-parent/",
				"color": "blue",
				"buildable": true,
				"lastBuild": {"number": 3, "result": "FAILURE", "building": false, "timestamp": 1700000100000, "duration": 500}
			}
		]
	}`
	// nested folder with spaces
	f.jobJSON["job/team/job/app with spaces"] = `{
		"name": "app with spaces",
		"fullName": "team/app with spaces",
		"_class": "com.cloudbees.hudson.plugins.folder.Folder",
		"jobs": [
			{
				"name": "deploy",
				"fullName": "team/app with spaces/deploy",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/team/job/app%20with%20spaces/job/deploy/",
				"color": "blue",
				"buildable": true,
				"lastBuild": {"number": 9, "result": "SUCCESS", "building": false, "timestamp": 1700000200000, "duration": 200}
			}
		]
	}`
	// multibranch children (branches)
	f.jobJSON["job/team/job/mb"] = `{
		"name": "mb",
		"fullName": "team/mb",
		"_class": "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject",
		"jobs": [
			{
				"name": "main",
				"fullName": "team/mb/main",
				"_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
				"url": "http://jenkins/job/team/job/mb/job/main/",
				"color": "blue",
				"buildable": true,
				"lastBuild": {"number": 4, "result": "SUCCESS", "building": false, "timestamp": 1700000300000, "duration": 300}
			},
			{
				"name": "PR-12",
				"fullName": "team/mb/PR-12",
				"_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
				"url": "http://jenkins/job/team/job/mb/job/PR-12/",
				"color": "red",
				"buildable": true,
				"lastBuild": {"number": 2, "result": "FAILURE", "building": false, "timestamp": 1700000400000, "duration": 400}
			}
		]
	}`
	// matrix parent + children
	f.jobJSON["job/team/job/matrix-parent"] = `{
		"name": "matrix-parent",
		"fullName": "team/matrix-parent",
		"_class": "hudson.matrix.MatrixProject",
		"jobs": [
			{
				"name": "axis=linux",
				"fullName": "team/matrix-parent/axis=linux",
				"_class": "hudson.matrix.MatrixConfiguration",
				"url": "http://jenkins/job/team/job/matrix-parent/job/axis=linux/",
				"color": "blue",
				"buildable": true
			}
		]
	}`
}

func (f *jenkinsFixture) handleJobOrBuildAPI(w http.ResponseWriter, r *http.Request, path string) {
	// /job/X/api/json or /job/X/job/Y/api/json or /job/X/N/api/json
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// detect build number segment before api
	for i := 0; i < len(parts)-1; i++ {
		if parts[i+1] == "api" && isAllDigits(parts[i]) {
			key := strings.Join(parts[:i+1], "/")
			f.mu.Lock()
			body, ok := f.buildJSON[key]
			f.mu.Unlock()
			if !ok {
				// default build payload
				n, _ := strconv.Atoi(parts[i])
				body = defaultBuildJSON(n)
			}
			f.writeJSON(w, body)
			return
		}
	}
	// job detail
	jobKey := strings.TrimSuffix(path, "/api/json")
	jobKey = strings.Trim(jobKey, "/")
	f.mu.Lock()
	body, ok := f.jobJSON[jobKey]
	f.mu.Unlock()
	if !ok {
		body = defaultJobJSON()
	}
	f.writeJSON(w, body)
}

func (f *jenkinsFixture) handleProgressive(w http.ResponseWriter, r *http.Request, path string) {
	// .../job/demo/7/logText/progressiveText
	start, _ := strconv.Atoi(r.URL.Query().Get("start"))
	// strip /logText/progressiveText
	idx := strings.Index(path, "/logText/progressiveText")
	prefix := strings.Trim(path[:idx], "/")
	f.mu.Lock()
	full, hasBody := f.progressive[prefix]
	synSize, hasSize := f.progressiveSize[prefix]
	f.mu.Unlock()
	if !hasBody && !hasSize {
		http.NotFound(w, r)
		return
	}
	if start < 0 {
		start = 0
	}

	// Jenkins-like: offer entire remainder (no server-side length limit).
	// LOG-001 clients stop reading after the requested length and close the body;
	// bytesServed counts only bytes actually written (early client close stops us).
	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	w.Header().Set("X-More-Data", "false")

	// countingWriter updates bytesServed on every successful Write so client-side
	// measurements are not racy with post-loop accounting (LOG-001 early close).
	cw := &countingWriter{w: w, n: &f.bytesServed}

	if hasBody {
		if start > len(full) {
			start = len(full)
		}
		chunk := full[start:]
		w.Header().Set("X-Text-Size", strconv.Itoa(len(full)))
		// Small writes so early Close is reflected in bytesServed promptly.
		_, _ = writeInChunks(cw, []byte(chunk), 8*1024)
		return
	}

	// Synthetic sized log (PERF-001): stream remainder without full materialization.
	if start > synSize {
		start = synSize
	}
	remain := synSize - start
	w.Header().Set("X-Text-Size", strconv.Itoa(synSize))
	_, _ = writeSyntheticLog(cw, start, remain)
}

// countingWriter tallies bytes actually accepted by the ResponseWriter.
type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	nw, err := c.w.Write(p)
	if nw > 0 && c.n != nil {
		c.n.Add(int64(nw))
	}
	return nw, err
}

// writeInChunks writes b in chunkSize pieces so a client that closes after a
// LimitReader cap causes Write to fail without pushing the entire remainder.
func writeInChunks(w io.Writer, b []byte, chunkSize int) (int, error) {
	if chunkSize <= 0 {
		chunkSize = 8 * 1024
	}
	written := 0
	for written < len(b) {
		end := written + chunkSize
		if end > len(b) {
			end = len(b)
		}
		nw, err := w.Write(b[written:end])
		written += nw
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// writeSyntheticLog writes n bytes of a deterministic alphabet cycle starting at
// logical offset start (so total X-Text-Size content is position-consistent).
// Returns bytes actually written (may be < n if the client closes early).
func writeSyntheticLog(w io.Writer, start, n int) (int, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const alphaLen = len(alphabet)
	// Modest chunks so LOG-001 early close is visible in fixture accounting
	// without huge per-Write overhead. Flush when possible so httptest/pipe
	// does not silently buffer an entire 1 MiB remainder (Rocky CI flake).
	const bufSize = 8 * 1024
	buf := make([]byte, bufSize)
	flusher, _ := w.(http.Flusher)
	// countingWriter does not implement Flusher; unwrap for flush only.
	if flusher == nil {
		if cw, ok := w.(*countingWriter); ok {
			flusher, _ = cw.w.(http.Flusher)
		}
	}
	written := 0
	for written < n {
		chunk := n - written
		if chunk > bufSize {
			chunk = bufSize
		}
		for i := 0; i < chunk; i++ {
			buf[i] = alphabet[(start+written+i)%alphaLen]
		}
		nw, err := w.Write(buf[:chunk])
		written += nw
		if err != nil {
			return written, err
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
	return written, nil
}

func (f *jenkinsFixture) handleCancelItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)
	f.mu.Lock()
	f.cancelCalls.Add(1)
	if crumb := r.Header.Get("Jenkins-Crumb"); crumb != "" {
		f.lastCancelCrumb = crumb
	}
	// Also accept any header that matches a known crumb field name from fixture.
	if f.lastCancelCrumb == "" {
		if c := r.Header.Get(".crumb"); c != "" {
			f.lastCancelCrumb = c
		}
	}
	missing := f.cancelMissingIDs[id]
	status := f.cancelStatus
	f.mu.Unlock()
	if missing {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
		return
	}
	if status == 0 {
		status = http.StatusFound // Jenkins-like 302
	}
	w.WriteHeader(status)
	if status >= 400 {
		_, _ = w.Write([]byte("cancel failed"))
	}
}

// setQueuedItem installs a still-waiting queue item (no executable) for cancel tests.
func (f *jenkinsFixture) setQueuedItem(id int, jobName string) {
	if jobName == "" {
		jobName = "demo"
	}
	body := `{
		"id": ` + strconv.Itoa(id) + `,
		"task": {"name": "` + jobName + `", "url": "http://jenkins/job/` + jobName + `/"},
		"why": "Waiting for next available executor",
		"inQueueSince": 1700000000000,
		"stuck": false,
		"buildable": true,
		"params": "",
		"cancelled": false,
		"executable": null
	}`
	f.mu.Lock()
	f.queueJSON[id] = body
	f.mu.Unlock()
}

// setQueueItemMissing makes GetQueueItem return 404 for id.
func (f *jenkinsFixture) setQueueItemMissing(id int) {
	// Represent missing by empty sentinel handled in handleQueueItem.
	f.mu.Lock()
	f.queueJSON[id] = "__missing__"
	f.mu.Unlock()
}

func (f *jenkinsFixture) handleQueueItem(w http.ResponseWriter, path string) {
	// /queue/item/42/api/json
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, nil)
		return
	}
	id, err := strconv.Atoi(parts[2])
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	f.mu.Lock()
	body, ok := f.queueJSON[id]
	f.mu.Unlock()
	if ok && body == "__missing__" {
		http.NotFound(w, nil)
		return
	}
	if !ok {
		// default assigned executable
		body = `{
			"id": ` + strconv.Itoa(id) + `,
			"task": {"name": "demo", "url": "http://jenkins/job/demo/"},
			"why": null,
			"inQueueSince": 1700000000000,
			"stuck": false,
			"buildable": false,
			"params": "",
			"cancelled": false,
			"executable": {
				"number": 9,
				"url": "http://jenkins/job/demo/9/",
				"building": false,
				"result": "SUCCESS",
				"timestamp": 1700000001000,
				"duration": 1200,
				"estimatedDuration": 1000,
				"displayName": "#9"
			}
		}`
	}
	f.writeJSON(w, body)
}

func (f *jenkinsFixture) writeJSON(w http.ResponseWriter, body string) {
	f.bytesServed.Add(int64(len(body)))
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, body)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func defaultJobJSON() string {
	return `{
		"name": "demo",
		"url": "http://jenkins/job/demo/",
		"color": "blue",
		"buildable": true,
		"description": "demo job",
		"lastBuild": {"number": 10, "url": "http://jenkins/job/demo/10/", "building": true, "result": null},
		"lastSuccessfulBuild": {"number": 8, "building": false, "result": "SUCCESS"},
		"lastFailedBuild": {"number": 9, "building": false, "result": "FAILURE"},
		"lastUnstableBuild": null,
		"lastCompletedBuild": {"number": 9, "building": false, "result": "FAILURE"},
		"builds": [
			{"number": 10, "url": "http://jenkins/job/demo/10/", "result": null, "building": true, "timestamp": 1700000030000, "duration": 0, "displayName": "#10"},
			{"number": 9, "url": "http://jenkins/job/demo/9/", "result": "FAILURE", "building": false, "timestamp": 1700000020000, "duration": 2000, "displayName": "#9",
				"actions":[{"_class":"hudson.model.ParametersAction","parameters":[{"name":"BRANCH","value":"main"},{"name":"API_TOKEN","value":"super-secret-token-value"}]}]},
			{"number": 8, "url": "http://jenkins/job/demo/8/", "result": "SUCCESS", "building": false, "timestamp": 1700000010000, "duration": 1500, "displayName": "#8"},
			{"number": 7, "url": "http://jenkins/job/demo/7/", "result": "ABORTED", "building": false, "timestamp": 1700000000000, "duration": 1000, "displayName": "#7"}
		],
		"property": []
	}`
}

func defaultBuildJSON(n int) string {
	b, _ := json.Marshal(map[string]any{
		"number":            n,
		"url":               "http://jenkins/job/demo/" + strconv.Itoa(n) + "/",
		"result":            "SUCCESS",
		"building":          false,
		"timestamp":         1700000000000,
		"duration":          1500,
		"estimatedDuration": 1000,
		"displayName":       "#" + strconv.Itoa(n),
		"actions":           []any{},
	})
	return string(b)
}

// setGraphFixture installs upstream/downstream + cycle-capable builds for GRAPH-001.
func (f *jenkinsFixture) setGraphFixture() {
	// root service build caused by upstream deploy; triggers downstream smoke
	f.buildJSON["job/service/5"] = `{
		"number": 5,
		"result": "FAILURE",
		"building": false,
		"timestamp": 1700000500000,
		"duration": 5000,
		"displayName": "#5",
		"actions": [{
			"_class": "hudson.model.CauseAction",
			"causes": [{
				"_class": "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "deploy",
				"upstreamBuild": 3,
				"shortDescription": "Started by upstream project \"deploy\" build number 3"
			}]
		}],
		"downstreamBuilds": [
			{"jobName": "smoke", "buildNumber": 2}
		]
	}`
	f.buildJSON["job/deploy/3"] = `{
		"number": 3,
		"result": "SUCCESS",
		"building": false,
		"timestamp": 1700000400000,
		"duration": 3000,
		"displayName": "#3",
		"actions": [],
		"downstreamBuilds": [
			{"jobName": "service", "buildNumber": 5}
		]
	}`
	f.buildJSON["job/smoke/2"] = `{
		"number": 2,
		"result": "FAILURE",
		"building": false,
		"timestamp": 1700000600000,
		"duration": 1000,
		"displayName": "#2",
		"actions": [{
			"_class": "hudson.model.CauseAction",
			"causes": [{
				"_class": "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "service",
				"upstreamBuild": 5,
				"shortDescription": "Started by upstream project \"service\" build number 5"
			}]
		}]
	}`
	// Cycle A <-> B
	f.buildJSON["job/cycleA/1"] = `{
		"number": 1,
		"result": "FAILURE",
		"building": false,
		"timestamp": 1700000700000,
		"duration": 100,
		"actions": [{
			"_class": "hudson.model.CauseAction",
			"causes": [{
				"_class": "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "cycleB",
				"upstreamBuild": 1,
				"shortDescription": "cycle"
			}]
		}],
		"downstreamBuilds": [{"jobName": "cycleB", "buildNumber": 1}]
	}`
	f.buildJSON["job/cycleB/1"] = `{
		"number": 1,
		"result": "FAILURE",
		"building": false,
		"timestamp": 1700000710000,
		"duration": 100,
		"actions": [{
			"_class": "hudson.model.CauseAction",
			"causes": [{
				"_class": "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "cycleA",
				"upstreamBuild": 1,
				"shortDescription": "cycle"
			}]
		}],
		"downstreamBuilds": [{"jobName": "cycleA", "buildNumber": 1}]
	}`
}

func (f *jenkinsFixture) setWFAPILog(jobPath string, build int, nodeID, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build) + "/" + nodeID
	f.wfapiLogJSON[key] = body
}

func (f *jenkinsFixture) setArtifact(jobPath string, build int, relPath string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build) + "/" + strings.Trim(relPath, "/")
	f.artifactBytes[key] = body
}

func (f *jenkinsFixture) setBuildArtifactsJSON(jobPath string, build int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Trim(jobPath, "/") + "/" + strconv.Itoa(build)
	f.buildJSON[key] = body
}

func (f *jenkinsFixture) handleArtifact(w http.ResponseWriter, path string) {
	// /job/demo/7/artifact/reports/out.txt
	idx := strings.Index(path, "/artifact/")
	if idx < 0 {
		http.NotFound(w, nil)
		return
	}
	prefix := strings.Trim(path[:idx], "/")
	rel := strings.TrimPrefix(path[idx+len("/artifact/"):], "/")
	key := prefix + "/" + rel
	f.mu.Lock()
	body, ok := f.artifactBytes[key]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	f.artifactHits.Add(1)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}
