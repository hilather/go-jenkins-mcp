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

function sliceBetween(src: string, start: string, end: string): string {
  const a = src.indexOf(start);
  const b = src.indexOf(end);
  expect(a).toBeGreaterThan(-1);
  expect(b).toBeGreaterThan(a);
  return src.slice(a, b);
}

function residualCalloutSlice(src: string): string {
  const start = src.indexOf("<ResidualCallout");
  const end = src.indexOf("</ResidualCallout>");
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  return src.slice(start, end);
}

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

  it("Access ResidualCallout is static; fleet_sot stays on the status line", () => {
    const callout = residualCalloutSlice(accessSrc);
    expect(callout).toContain("ACCESS_RESIDUAL_DETAILS");
    expect(callout).not.toContain("fleet_sot");
    expect(callout).not.toContain("data.residual");
    expect(callout).not.toContain("data.notes");

    const status = sliceBetween(accessSrc, 'role="status"', "subjects.users");
    expect(status).toContain("available=");
    expect(status).toContain("fleet_sot=");
    expect(status).toContain("path_base=");

    const banner = sliceBetween(accessSrc, "banner warn", 'role="status"');
    expect(banner).not.toContain("fleet_sot");
  });

  it("Policy ResidualCallout is hoisted before the overlay editor card", () => {
    const page = policySrc.slice(policySrc.indexOf("export function PolicyPage"));
    const residualAt = page.indexOf("POLICY_RESIDUAL_CAVEAT");
    const overlayAt = page.indexOf("Pilot overlay (");
    expect(residualAt).toBeGreaterThan(-1);
    expect(overlayAt).toBeGreaterThan(-1);
    expect(residualAt).toBeLessThan(overlayAt);
    expect(page).not.toContain("Pilot pilot overlay");
  });

  it("Audit filters use form-field; ResidualCallout is HOST copy only", () => {
    expect(auditSrc).toContain('className="form-field"');
    expect(auditSrc).toContain('className="form-field form-field-wide"');
    expect(auditSrc).not.toContain('className="field"');
    const callout = residualCalloutSlice(auditSrc);
    expect(callout).toContain("AUDIT_RESIDUAL_DETAILS");
    expect(callout).not.toContain("settingsQ");
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
    expect(cacheSrc).toContain("Nothing to reclaim.");
    expect(cacheSrc).not.toMatch(/Dry-run found nothing/);
    expect(auditSrc).toContain("EmptyState");
    expect(auditSrc).toContain("No matching events");
    expect(auditSrc).toContain("No event selected");
  });

  it("Doctor page-level ResidualCallout is always on; card is DL only", () => {
    const card = sliceBetween(
      doctorSrc,
      "function DoctorGatewayResidualCard",
      "export function DoctorPage",
    );
    expect(card).not.toContain("ResidualCallout");

    const page = doctorSrc.slice(doctorSrc.indexOf("export function DoctorPage"));
    const headerAt = page.indexOf("PageHeader");
    const residualAt = page.indexOf("<ResidualCallout");
    const runAt = page.indexOf("Run doctor");
    expect(headerAt).toBeGreaterThan(-1);
    expect(residualAt).toBeGreaterThan(headerAt);
    expect(runAt).toBeGreaterThan(residualAt);
    expect(page.slice(headerAt, residualAt)).not.toContain("gatewayResidual");
    expect(page).toContain("DOCTOR_RESIDUAL_CAVEAT");
    expect(page).toContain('badge="HOST-007"');
  });
});
