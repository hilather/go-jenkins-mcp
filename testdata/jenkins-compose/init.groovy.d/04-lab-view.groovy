// TST-001: lab view listing mock-inv-* jobs (list_views / view filter drills).
// Runs after mock fixtures are seeded (03-mock-fixtures.groovy).

import java.util.logging.Logger
import hudson.model.ListView
import jenkins.model.Jenkins

def log = Logger.getLogger("init.mcp.lab-view")
def instance = Jenkins.get()
def viewName = "mock-investigations"

def view = instance.getView(viewName)
if (view == null) {
    view = new ListView(viewName)
    view.setDescription("Disposable lab view for mock-inv-* MCP fixture jobs (TST-001)")
    instance.addView(view)
    log.info("Created view ${viewName}")
} else {
    log.info("View ${viewName} already exists")
}

instance.getAllItems().each { item ->
    def name = item?.getFullName() ?: item?.getName()
    if (name != null && name.startsWith("mock-inv-")) {
        try {
            if (!view.contains(item)) {
                view.add(item)
            }
        } catch (Throwable t) {
            log.warning("Could not add ${name} to view ${viewName}: ${t.message}")
        }
    }
}

instance.save()
