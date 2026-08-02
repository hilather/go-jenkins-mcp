// Ensure setup wizard stays off (JAVA_OPTS also sets this).
// JCasC owns security realm + jwt-auth-filter config.
import jenkins.model.Jenkins
import jenkins.install.InstallState

def j = Jenkins.get()
if (j.installState != null && j.installState.isSetupComplete() == false) {
  j.installState = InstallState.INITIAL_SETUP_COMPLETED
  j.save()
}
