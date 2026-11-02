import type { ReactNode } from "react";
import type { NormalizedReport } from "../api/universal";
import "./PlatformConfigurationPage.css";

type Section = "Rules" | "Network Objects" | "Service Objects" | "NAT Rules" | "Routes" | "Configuration";
import type { PlatformDetails } from "../api/platformConfiguration";

type RecordValue = Record<string, unknown>;

function objectOf(value: unknown): RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as RecordValue : {};
}
function records(value: unknown): RecordValue[] {
  return Array.isArray(value) ? value.filter((v): v is RecordValue =>
    v !== null && typeof v === "object" && !Array.isArray(v)) : [];
}
function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}
function display(value: unknown): string {
  if (value === null || value === undefined) return "Not recorded";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number" || typeof value === "string") return String(value);
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string").join(", ") || "None";
  return "Not recorded";
}
function Info({ children }: { children: ReactNode }) {
  return <p className="pc-note">{children}</p>;
}
function Grid({ items }: { items: Array<[string, string]> }) {
  return <div className="pc-grid">{items.map(([label, value]) =>
    <div className="pc-stat" key={label}><span>{label}</span><strong>{value}</strong></div>
  )}</div>;
}
function Table({ headings, rows }: { headings: string[]; rows: string[][] }) {
  return <div className="pc-table-scroll"><table className="pc-table">
    <thead><tr>{headings.map((h) => <th key={h} scope="col">{h}</th>)}</tr></thead>
    <tbody>{rows.map((row, i) => <tr key={i}>{row.map((cell, j) =>
      <td key={j}>{cell || "—"}</td>
    )}</tr>)}</tbody>
  </table></div>;
}
function Empty({ title, children }: { title: string; children: ReactNode }) {
  return <div className="pc-empty"><strong>{title}</strong><p>{children}</p></div>;
}

export default function PlatformConfigurationPage({ report, section, details }: {
  report: NormalizedReport;
  section: Section;
  details: PlatformDetails | null;
}) {
  const platform = report.platform.platform_id;
  const present = details?.platform_id === platform;
  const config = present ? objectOf(details.configuration) : {};
  const suricata = platform === "suricata";
  const snort = platform === "snort";
  const fortios = platform === "fortios";
  const ids = suricata || snort;
  const ruleRows = records(config.ids_rules);
  const policies = records(config.firewall_policies);
  const headline = ids && section === "Rules" ? "IDS Detection Rules" : section;

  let view: ReactNode;
  if (!present) {
    view = <Empty title="Configuration inventory not available">
      This analysis has security findings, but the server did not return structured configuration details.
      Return to Dashboard and analyze the file again. The universal configuration-detail request may not have completed. No missing values are assumed to be zero.
    </Empty>;
  } else if (platform === "f5_bigip") {
    if (section === "Configuration") {
      view = <>
        <Grid items={[
          ["SSL / HTTP profiles parsed", display(config.f5_phase1_profile_count)],
          ["Virtual servers parsed", display(config.f5_phase1_virtual_count)],
          ["Phase 1 findings", display(config.f5_phase1_findings_count)],
          ["Policy review observations", display(config.f5_phase1_observations_count)],
        ]}/>
        <Info>These are counts from the F5 BIG-IP Phase 1 analysis response, not a complete device inventory. The findings and detailed evidence remain in the Findings pane and PDF. Inherited settings, additional objects and runtime deployment have not been verified.</Info>
      </>;
    } else {
      view = <Empty title="Not assessed by F5 Phase 1">
        This page does not yet provide a complete F5 BIG-IP {section.toLowerCase()} inventory.
        Phase 1 analyzes supported SSL and HTTP profile settings and their explicitly visible virtual-server associations. Absence of inventory data does not indicate that the device has no such objects.
      </Empty>;
    }
  } else if (section === "Rules" && ids) {
    view = <>
      <Grid items={[
        ["Inline parsed rules", String(ruleRows.length)],
        ...(suricata ? [["Referenced rule files", display(config.rule_file_entries)] as [string, string]] : []),
        ...(snort ? [["Include directives", display(config.include_directives)] as [string, string]] : []),
      ]}/>
      {ruleRows.length ? <Table
        headings={["Line", "Action", "Protocol", "SID", ...(suricata ? ["GID"] : []), "Revision", "Enabled"]}
        rows={ruleRows.map((rule) => [
          display(rule.line_number), display(rule.action), display(rule.protocol),
          display(rule.sid), ...(suricata ? [display(rule.gid)] : []),
          display(rule.revision), display(rule.enabled),
        ])}
      /> : <Empty title="No inline rules found">
        {suricata ? "The YAML may reference external .rules files. Referenced files were not opened or parsed. Upload a standalone .rules file with Suricata explicitly selected to inspect its inline rules." : "No supported inline detection rules were parsed from this upload."}
      </Empty>}
      <Info>Only the supported rule-header subset is represented. This is not an effective ruleset or runtime evaluation.</Info>
    </>;
  } else if (section === "Rules" && fortios) {
    view = policies.length ? <Table
      headings={["Policy", "Action", "Source", "Destination", "Service", "Log traffic"]}
      rows={policies.map((policy) => [
        display(policy.policy_id), display(policy.action), display(policy.srcaddr),
        display(policy.dstaddr), display(policy.service), display(policy.logtraffic),
      ])}
    /> : <Empty title="No policies in parsed subset">No firewall policies were extracted from the supplied text.</Empty>;
  } else if (section === "Network Objects" && suricata) {
    view = <><Grid items={[["HOME_NET setting visible", display(config.home_net_visible)]]}/>
      <Info>Suricata uses YAML network variables rather than ASA-style address objects. The current parser reports whether HOME_NET is visible, not its value or a complete list of variables.</Info>
    </>;
  } else if (section === "Network Objects" && snort) {
    const items = strings(config.network_variables);
    view = items.length ? <div className="pc-chips">{items.map((x) => <span className="pc-chip" key={x}>{x}</span>)}</div>
      : <Empty title="No parsed network variables">No supported network variables were extracted from this file.</Empty>;
  } else if (section === "Network Objects" && fortios) {
    const items = strings(config.address_object_names);
    view = items.length ? <div className="pc-chips">{items.map((x) => <span className="pc-chip" key={x}>{x}</span>)}</div>
      : <Empty title="No address objects extracted">No named firewall address objects were found in the supported parser subset.</Empty>;
  } else if (section === "Service Objects" && fortios) {
    const items = strings(config.custom_service_names);
    view = items.length ? <div className="pc-chips">{items.map((x) => <span className="pc-chip" key={x}>{x}</span>)}</div>
      : <Empty title="No custom services extracted">No named custom services were extracted from the supplied FortiOS text.</Empty>;
  } else if (section === "Service Objects" && ids) {
    view = <Empty title="Not applicable to this IDS model">
      This parser does not build separate firewall service objects. IDS rules may use protocol and port fields, but those are not ASA-style service objects.
    </Empty>;
  } else if (section === "NAT Rules" && ids) {
    view = <Empty title="Not applicable">
      Suricata and Snort are IDS/IPS engines; this configuration analyzer does not model them as firewalls with NAT rules. No NAT configuration was assessed.
    </Empty>;
  } else if (section === "Routes" && ids) {
    view = <Empty title="Not applicable">
      Network routing is not represented by Suricata or Snort detection rules. Host or device routing tables were not uploaded or assessed.
    </Empty>;
  } else if (section === "NAT Rules" || section === "Routes") {
    view = <Empty title="Not assessed in the current FortiOS parser">
      The supported FortiOS subset does not extract {section.toLowerCase()}; this does not mean the device has none configured.
    </Empty>;
  } else if (section === "Configuration" && suricata) {
    view = <><Grid items={[
      ["Suricata YAML recognized", display(config.yaml_recognized)],
      ["HOME_NET setting visible", display(config.home_net_visible)],
      ["Rule file entries", display(config.rule_file_entries)],
      ["AF-PACKET interfaces", display(config.af_packet_interfaces)],
      ["EVE logging explicitly enabled", display(config.eve_log_enabled)],
    ]}/><Info>Only recognized YAML settings are displayed. The uploaded raw YAML is not returned by the normalized API, and rule-file references are never opened.</Info></>;
  } else if (section === "Configuration" && snort) {
    view = <><Grid items={[
      ["Inline rules", String(ruleRows.length)],
      ["Include directives", display(config.include_directives)],
      ["Output directives", display(config.output_directives)],
    ]}/><Info>These are visible Snort configuration statistics, not proof of the effective loaded configuration.</Info></>;
  } else if (section === "Configuration" && fortios) {
    view = <><Grid items={[
      ["Firewall policies", String(policies.length)],
      ["Address objects", String(strings(config.address_object_names).length)],
      ["Custom services", String(strings(config.custom_service_names).length)],
      ["Interfaces", String(strings(config.interface_names).length)],
    ]}/><Info>Only the implemented FortiOS CLI subset is represented. VDOMs, defaults and effective policy behavior are outside scope.</Info></>;
  } else {
    view = <Empty title="No configuration inventory">This section is not available from this report.</Empty>;
  }

  return <div className="pc-page">
    <header className="pc-header"><p className="pc-kicker">{report.platform.display_name}</p>
      <h1>{headline}</h1><p>Structured information extracted from the uploaded configuration.</p>
    </header>
    <section className="pc-panel">{view}</section>
    <section className="pc-panel pc-footnote"><h2>Analysis limits</h2>
      <p>Only data returned by the registered platform analyzer is shown. A missing field or empty list does not prove a secure or empty device configuration.</p>
    </section>
  </div>;
}
