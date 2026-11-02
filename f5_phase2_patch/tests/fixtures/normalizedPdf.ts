import type { F5Phase1Review } from "../api/f5Phase1";
  const f5Phase1Review = (report as NormalizedReport & { f5_phase1_review?: F5Phase1Review }).f5_phase1_review;
  if (f5Phase1Review) {
    section("F5 BIG-IP Phase 1 - Detailed technical evidence");
    text("Static subset: F5-001 TLS 1.3, F5-002 cipher policy review, F5-003 server certificate validation, F5-007 HSTS. No live TLS probe or deployment verification.", {
      size: 8.5, color: COLORS.muted, spaceAfter: 7,
    });
    text(`Profiles: ${f5Phase1Review.total_profiles} | Virtual servers: ${f5Phase1Review.total_virtual_servers} | Findings: ${f5Phase1Review.findings.length} | Review observations: ${f5Phase1Review.review_observations.length}`, {
      size: 9, bold: true, spaceAfter: 7,
    });
    const printF5Items = (items: F5Phase1Review["findings"], heading: string) => {
      text(heading, { bold: true, color: COLORS.blue, size: 9.1, spaceAfter: 6 });
      if (!items.length) text("No items returned in this category.", { size: 8.5, color: COLORS.muted });
      items.slice(0, 500).forEach((item) => {
        ensure(68);
        text(`${item.code} | ${item.title} | ${item.severity.toUpperCase()}`, { bold: true, size: 9.1, spaceAfter: 4 });
        text(`Object: ${item.affected_object} (${item.object_type}) | Source line: ${item.line_number ?? "not available"} | Confidence: ${item.confidence}`, {
          size: 8.2, color: COLORS.muted, spaceAfter: 3,
        });
        text(`Setting: ${item.evidence.setting} | Observed: ${item.evidence.observed}`, { size: 8.4, indent: 8, spaceAfter: 4 });
        if (item.associated_virtual_servers.length) {
          text(`Associated virtual servers: ${item.associated_virtual_servers.join(", ")}`, {
            size: 8.1, indent: 8, spaceAfter: 4,
          });
        }
        text(item.description, { indent: 8, size: 8.5, spaceAfter: 4 });
        text(`Recommendation: ${item.recommendation}`, { indent: 8, size: 8.5, spaceAfter: 5 });
        text(`Limitation: ${item.limitations}`, { indent: 8, color: COLORS.muted, size: 8, spaceAfter: 8 });
      });
      if (items.length > 500) text("Further F5 records omitted because the PDF safety limit was reached; refer to the complete JSON export.", {
        color: COLORS.muted, size: 8.2,
      });
    };
    printF5Items(f5Phase1Review.findings, "CONFIGURATION FINDINGS");
    printF5Items(f5Phase1Review.review_observations, "POLICY REVIEW / INSUFFICIENT EVIDENCE (NOT CONFIRMED VULNERABILITIES)");
    text("F5 PHASE 1 COVERAGE LIMITATIONS", { bold: true, color: COLORS.blue, size: 9, spaceAfter: 5 });
    f5Phase1Review.limitations.forEach((item) => text(`Limitation: ${item}`, {
      size: 8.2, color: COLORS.muted, spaceAfter: 5,
    }));
  }

