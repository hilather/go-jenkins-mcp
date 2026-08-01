// TST-001: disposable security bootstrap (admin + API token).
// Password from env JENKINS_ADMIN_PASSWORD (default "test") — lab only, never production.
// API token is written to $JENKINS_HOME/mcp-api-token (not committed; container-local).

import java.util.logging.Logger
import jenkins.model.Jenkins
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.model.User
import jenkins.security.ApiTokenProperty

def log = Logger.getLogger("init.mcp.security")
def instance = Jenkins.get()

def password = System.getenv("JENKINS_ADMIN_PASSWORD")
if (password == null || password.trim().isEmpty()) {
    password = "test"
}

def realm = new HudsonPrivateSecurityRealm(false)
if (realm.getUser("admin") == null) {
    realm.createAccount("admin", password)
    log.info("Created disposable admin user")
} else {
    log.info("admin user already present")
}
instance.setSecurityRealm(realm)

def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(strategy)

// Built-in node executors for freestyle/pipeline smoke builds.
instance.setNumExecutors(2)

// Ephemeral API token for live tests (never log the plain value).
def user = User.getById("admin", true)
def tokenProp = user.getProperty(ApiTokenProperty.class)
if (tokenProp == null) {
    tokenProp = new ApiTokenProperty()
    user.addProperty(tokenProp)
}

// Prefer a stable token name so re-runs on the same volume replace cleanly.
def tokenName = "mcp-live-smoke"
// Revoke prior tokens with this name if the store supports it (best-effort).
try {
    def store = tokenProp.tokenStore
    // generateNewToken always creates a fresh plain value.
    def created = store.generateNewToken(tokenName)
    def root = instance.getRootDir()
    def tokenFile = new File(root, "mcp-api-token")
    def userFile = new File(root, "mcp-api-user")
    tokenFile.text = created.plainValue
    userFile.text = "admin"
    // Restrictive perms where the FS supports it.
    try {
        tokenFile.setReadable(false, false)
        tokenFile.setReadable(true, true)
        tokenFile.setWritable(false, false)
        tokenFile.setWritable(true, true)
    } catch (Throwable ignored) {
        // ignore permission tweaks on restricted FS
    }
    user.save()
    log.info("Wrote disposable API token material under JENKINS_HOME (mcp-api-token); plain value not logged")
} catch (Throwable t) {
    log.severe("Failed to generate API token: ${t.class.name}: ${t.message}")
    throw t
}

instance.save()
