# Deploy — systemd (host binary)

**Support status:** Experimental

Pattern for running a packaged binary under systemd on Tier-1 Linux:

1. Install package or place `jenkins-mcp` on a system path  
2. Create a dedicated service user  
3. XDG paths under that user  
4. Unit: `ExecStart=/usr/bin/jenkins-mcp serve …` with RO defaults  
5. Restart=`on-failure`; no secrets in unit files — use keyring or credential files with mode 0600  

Prefer Compose/K8s scaffolds for shared gateway hosts unless your platform standard is systemd.
