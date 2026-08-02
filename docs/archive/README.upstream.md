# Jenkins MCP Server (Go)

**Overview**
- Purpose: Pure Go MCP server exposing Jenkins API functionality as MCP tools.
- Transport: stdio (newline-delimited JSON) via `mcp-go-sdk`.

**Features**
- Tool: `jenkins_get_jobs`
  - Description: Get list of Jenkins jobs with their current status
  - Arguments: None
  - Returns: JSON array of jobs with basic information: `name`, `url`, `color`, `buildable`, `description`, and `lastBuild` when available

- Tool: `jenkins_get_job`
  - Description: Get detailed information about a specific Jenkins job by name, including recent builds and any queued items for this job
  - Arguments:
    - `name` (required) - Name of the Jenkins job
    - `max_builds` (optional, default: 20) - Maximum number of recent builds to return
  - Returns: JSON object with detailed job information including recent build history and `queuedBuilds` (if present)

- Tool: `jenkins_get_running_builds`
  - Description: Get list of currently running and queued Jenkins builds
  - Arguments: None
  - Returns: JSON object with:
    - `builds`: running builds with fields: `jobName`, `buildNumber`, `url`, `startTime` (RFC3339 string), `duration` (human-readable), optional `progress`
    - `queuedBuilds`: queued items with fields: `jobName`, `url`, `queueId`, `why`, `queuedSince` (RFC3339 string), `stuck`, `buildable`, optional `parameters`

- Tool: `jenkins_get_build`
  - Description: Get detailed information about a specific Jenkins build by job name and build number
  - Arguments:
    - `job_name` (required) - Name/path of the Jenkins job (supports folders)
    - `build_number` (required) - Build number
  - Returns: JSON object with build details including `result`, `building`, timestamps, durations, display name, and extracted build `parameters`

- Tool: `jenkins_get_build_logs`
  - Description: Get build logs for a specific Jenkins job and build number with pagination support
  - Arguments: 
    - `job_name` (required) - Name of the Jenkins job
    - `build_number` (required) - Build number to get logs for
    - `offset` (optional, default: 0) - Starting byte offset in the log file
    - `length` (optional, default: 8192) - Maximum number of bytes to retrieve
  - Returns: JSON object with log metadata: `jobName`, `buildNumber`, `offset`, `length`, `totalSize`, `hasMore`, and `logs`

- Tool: `jenkins_get_build_log_tail`
  - Description: Get the tail of build logs - useful for quick failure analysis
  - Arguments:
    - `job_name` (required) - Name of the Jenkins job
    - `build_number` (required) - Build number to get logs for
    - `max_length` (optional, default: 8192) - Maximum number of bytes to retrieve from the end
  - Returns: JSON object with log metadata: `jobName`, `buildNumber`, `offset`, `length`, `totalSize`, `hasMore`, and `logs`

- Tool: `jenkins_start_job`
  - Description: Trigger a Jenkins job build with optional parameters
  - Arguments:
    - `job_name` (required) - Name/path of the Jenkins job (supports folders)
    - `parameters` (optional) - Object map of build parameters
  - Returns: JSON with `jobName` and `queueUrl` (if available), plus `queueId` when Jenkins returns a queue item. The server waits briefly for Jenkins to assign an executable and may also include `buildUrl` and `buildNumber`; total queue wait is bounded to 30 seconds.

- Tool: `jenkins_get_queue_item`
  - Description: Get the current state of a Jenkins queue item, including the assigned build when available
  - Arguments:
    - `queue_id` (required) - Jenkins queue item ID
  - Returns: JSON object with queue item details including `jobName`, `why`, `queuedSince`, `cancelled`, and `executable` when a build has been assigned

- Tool: `jenkins_wait_for_queue_item`
  - Description: Wait for a Jenkins queue item to receive a build assignment, be cancelled, or timeout
  - Arguments:
    - `queue_id` (required) - Jenkins queue item ID
    - `timeout_seconds` (optional, default: 30) - Maximum time to wait in seconds
    - `poll_interval_seconds` (optional, default: 2) - Polling interval in seconds
  - Returns: JSON object with `status` (`started`, `cancelled`, or `timeout`), `waitTime`, `timedOut`, latest `queueItem`, and `build` when assigned

- Tool: `jenkins_wait_for_running_build`
  - Description: Wait for a running Jenkins build to complete or timeout
  - Arguments:
    - `job_name` (required) - Name of the Jenkins job
    - `build_number` (required) - Build number to wait for
    - `timeout_seconds` (optional, default: 600) - Maximum time to wait in seconds
  - Returns: JSON object with build completion status and timing information

- Tool: `jenkins_search_builds`
  - Description: Search Jenkins builds by result and/or build parameters
  - Arguments:
    - `job_name` (required) - Name of the Jenkins job
    - `result` (optional) - Filter by build result: `SUCCESS`, `FAILURE`, `ABORTED`
    - `params` (optional) - Filter by build parameters as `key=value` strings; an empty value (`key=`) matches an empty or unset parameter
    - `limit` (optional, default: 5) - Maximum number of matching results to return
    - `max_lookback` (optional, default: 100) - Maximum number of builds to scan
  - Returns: JSON object with matching `builds` and `scanned` count

- Tool: `jenkins_stop_build`
  - Description: Stop a running Jenkins build by job name and build number
  - Arguments:
    - `job_name` (required) - Name/path of the Jenkins job (supports folders)
    - `build_number` (required) - Build number to stop
  - Returns: JSON object with `jobName`, `buildNumber`, and `stopped`

**Job Format**
Each job returned by `jenkins_get_jobs` and `jenkins_get_job` includes:
```json
{
  "name": "job-name",
  "url": "https://jenkins.example.com/job/job-name/",
  "color": "blue",
  "buildable": true,
  "description": "Job description",
  "recentBuilds": [
    {
      "number": 123,
      "url": "https://jenkins.example.com/job/job-name/123/",
      "building": false,
      "result": "SUCCESS",
      "timestamp": "2023-08-21T12:00:00Z",
      "duration": "2m0s"
    },
    {
      "number": 122,
      "url": "https://jenkins.example.com/job/job-name/122/",
      "building": false,
      "result": "SUCCESS",
      "timestamp": "2023-08-21T11:40:00Z",
      "duration": "1m58s"
    }
  ],
  "parameters": [
    {
      "name": "MERGE_FEATURE",
      "type": "StringParameterDefinition",
      "description": "Feature branch to merge",
      "defaultValue": "",
      "choices": []
    },
    {
      "name": "BUILD_TYPE",
      "type": "ChoiceParameterDefinition",
      "description": "Type of build to perform",
      "defaultValue": "release",
      "choices": ["debug", "release", "test"]
    }
  ]
}
```

Note: `recentBuilds` are sorted by build number (descending - most recent first) and both `lastBuild` and `recentBuilds` fields are omitted when empty.

Note: The `jenkins_get_job` tool returns individual jobs with full parameter information and recent build history (up to `max_builds`, default 20, sorted by number descending), while `jenkins_get_jobs` returns only basic job fields (no parameters or `recentBuilds`) for performance; it may include `lastBuild` when available.

**Running Build Format**
Each running build returned by `jenkins_get_running_builds` includes:
```json
{
  "jobName": "job-name",
  "buildNumber": 124,
  "url": "https://jenkins.example.com/job/job-name/124/",
  "startTime": "2023-08-21T12:01:40Z",
  "duration": "45s",
  "progress": 75
}
```

**Queued Build Format**
Each queued build item includes:
```json
{
  "jobName": "job-name",
  "url": "https://jenkins.example.com/job/job-name/",
  "queueId": 19069,
  "why": "Build is waiting for an available executor",
  "queuedSince": "2023-08-21T12:01:00Z",
  "stuck": false,
  "buildable": true,
  "parameters": "PARAM1=foo\nPARAM2=bar"
}
```

**Build Logs Result**
`jenkins_get_build_logs` returns plain text containing the requested portion of the log. Control pagination via the `offset` and `length` arguments. Example output:
```
Started by user admin
Building in workspace /var/lib/jenkins/workspace/job-name
...
```

**Wait for Build Format**
Build wait results returned by `jenkins_wait_for_running_build` include:
```json
{
  "jobName": "job-name",
  "buildNumber": 124,
  "status": "success",
  "result": "SUCCESS",
  "duration": "2m0s",
  "waitTime": "45s",
  "timedOut": false
}
```

Status values:
- `success`: Build completed successfully
- `failure`: Build failed
- `unstable`: Build completed but with test failures or warnings
- `aborted`: Build was manually aborted
- `timeout`: Wait operation timed out before build completed
- `unknown`: Build completed with an unrecognized result

**Jenkins Color Codes**
- `blue`: Last build was successful
- `red`: Last build failed
- `yellow`: Last build was unstable
- `grey`: Job has never been built
- `disabled`: Job is disabled
- `aborted`: Last build was aborted
- `*_anime`: Job is currently building (e.g., `blue_anime`)

**Requirements**
- CLI: `-url <jenkins_url>` (required) - Jenkins server URL
- CLI: `-auth "<user>:<api_token>"` (optional) - Jenkins authentication credentials
- ENV: `JENKINS_MCP_AUTH="<user>:<api_token>"` (optional) - Alternative to `-auth` flag
- CLI: `-stdio` (default true) for stdio, or `-http <addr>` for Streamable HTTP.

**Authentication**
Authentication can be provided in two ways:
1. Command line flag: `-auth "user:token"`
2. Environment variable: `JENKINS_MCP_AUTH="user:token"`

If both are provided, the `-auth` flag takes precedence.

**Run (stdio)**
- Build: `go build -o jenkins-mcp-go .`
- Run (stdio): execute with required parameters; an MCP host (e.g., Claude Desktop) should launch this binary with stdio wiring.

Examples:
- `JENKINS_MCP_AUTH="myuser:myapitoken" ./jenkins-mcp-go -url "https://jenkins.example.com"`
- HTTP mode: `JENKINS_MCP_AUTH="myuser:myapitoken" ./jenkins-mcp-go -url "https://jenkins.example.com" -http :8080`

**Smithery / Hosts**
- Configure your MCP host to run this server over stdio with the required parameters.

**API Details**
- Uses Jenkins REST API `/api/json` endpoint to fetch job list
- Uses Jenkins REST API `/job/{jobName}/api/json` endpoint to fetch specific job details
- Uses Jenkins REST API `/computer/api/json` endpoint to fetch running builds from executors
- Uses Jenkins REST API `/queue/api/json` and `/queue/item/{queueId}/api/json` endpoints for queued builds and queue item tracking
- Uses Jenkins REST API `/job/{jobName}/{buildNumber}/logText/progressiveText` endpoint for build logs
- Implements smart tail log retrieval by calculating offset from total log size
- Implements proper basic authentication and includes Jenkins CSRF crumb for build triggers when available
- 30-second timeout for API calls, 60-second timeout for log retrieval
- Graceful error handling for missing jobs/builds
- Parses job names and build numbers from executor information
- Supports nested jobs/folders via Jenkins path convention `/job/<seg>/job/<seg>/...` and proper URL escaping
- Supports log pagination with offset and length parameters
- Optimized tail log retrieval for quick failure analysis

**Notes**
- Input validation: enforces required URL and auth parameters
- Auth format: must be "user:api_token" format
- Errors: returned as tool results with `isError=true` for LLM visibility
- Timestamps are RFC3339 strings; durations are human-readable (e.g., "45s", "2m5s")

**Transport**
- `-http <addr>` starts Streamable HTTP; otherwise `-stdio` runs by default.
- If `-stdio=false` and no `-http` is provided, the server exits with an error.

**TODO**
- Add more Jenkins tools (get build status, etc.)
- Add filtering options (by job name pattern, status, etc.)
- Add SSL certificate validation options
- Optionally return structured metadata for log tools
- Optional `wait` behavior modes for `jenkins_start_job`
