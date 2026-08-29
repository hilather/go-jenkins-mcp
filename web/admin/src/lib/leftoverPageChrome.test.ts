import { describe, expect, it } from "vitest";
import accessSrc from "../pages/AccessPage.tsx?raw";
import auditSrc from "../pages/AuditPage.tsx?raw";
import cacheSrc from "../pages/CachePage.tsx?raw";
import doctorSrc from "../pages/DoctorPage.tsx?raw";
import policySrc from "../pages/PolicyPage.tsx?raw";
import profilesSrc from "../pages/ProfilesPage.tsx?raw";

const PAGES: { name: string; src: string; caveat: string }[] = [
  { name: "Profiles", src: profilesSrc, caveat: "PROFILES_RESIDUAL_CAVEAT" },
  { name: "Policy", src: policySrc, caveat: "POLICY_RESIDUAL_CAVEAT" },
  { name: "Access", src: accessSrc, caveat: "ACCESS_RESIDUAL_CAVEAT" },
  { name: "Audit", src: auditSrc, caveat: "AUDIT_RESIDUAL_CAVEAT" },
  { name: "Doctor", src: doctorSrc, caveat: "DOCTOR_RESIDUAL_CAVEAT" },
  { name: "Cache", src: cacheSrc, caveat: "CACHE_RESIDUAL_CAVEAT" },
];

describe("leftover page chrome", () => {
  it.each(PAGES)("$name uses PageHeader, ResidualCallout, and exported caveat", ({ src, caveat }) => {
    expect(src).toContain("PageHeader");
    expect(src).toContain("ResidualCallout");
    expect(src).toContain(caveat);
  });

  it("Access uses current component contracts and form chrome", () => {
    expect(accessSrc).not.toMatch(/PageHeader[\s\S]*subtitle=/);
    expect(accessSrc).not.toContain("ErrorBanner title");
    expect(accessSrc).not.toContain("Loading label");
    expect(accessSrc).not.toContain("btn primary");
    expect(accessSrc).toContain("btn-primary");
    expect(accessSrc).toContain("form-field");
    expect(accessSrc).not.toContain("new Error(err)");
    expect(accessSrc).toContain("ErrorBanner error={actionError}");
    expect(accessSrc).toContain("Plain overlay bindings not available for edit");
  });

  it("Policy ResidualCallout is hoisted before the overlay editor card", () => {
    const residualAt = policySrc.indexOf("POLICY_RESIDUAL_CAVEAT");
    const overlayAt = policySrc.indexOf("Pilot pilot overlay");
    expect(residualAt).toBeGreaterThan(-1);
    expect(overlayAt).toBeGreaterThan(-1);
    expect(residualAt).toBeLessThan(overlayAt);
  });

  it("Profiles, Cache, Doctor, Audit wrap tables in table-scroll", () => {
    expect(profilesSrc).toContain("table-scroll");
    expect(cacheSrc).toContain("table-scroll");
    expect(doctorSrc).toContain("table-scroll");
    expect(auditSrc).toContain("table-scroll");
  });

  it("Profiles, Cache, Audit use EmptyState with required titles", () => {
    expect(profilesSrc).toContain("EmptyState");
    expect(profilesSrc).toContain("No profiles");
    expect(cacheSrc).toContain("EmptyState");
    expect(cacheSrc).toContain("No eviction candidates");
    expect(cacheSrc).not.toMatch(/Dry-run found nothing/);
    expect(auditSrc).toContain("EmptyState");
    expect(auditSrc).toContain("No matching events");
    expect(auditSrc).toContain("No event selected");
  });
});
