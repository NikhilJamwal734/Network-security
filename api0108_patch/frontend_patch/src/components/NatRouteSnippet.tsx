import type { NatRouteReachabilityReview } from "../api/universal";
import "./NatRouteSnippet.css";

export default function NatRouteSnippet({ review }: { review?: NatRouteReachabilityReview }) {
  if (!review) return null;
  const s = review.summary;
  return (
    <section className="ua-panel nrr-panel" aria-labelledby="nrr-title">
      <div className="nrr-heading">
        <h2 id="nrr-title">NAT, routing &amp; reachability</h2>
        <span>{review.status === "not_assessed" ? "Not assessed" : review.status === "limited" ? "Limited" : "Reviewed subset"}</span>
      </div>
      {review.status !== "not_assessed" ? (
        <>
          <div className="nrr-stats">
            <div><strong>{s.routes_resolved}</strong><span>Routes parsed</span></div>
            <div><strong>{s.nat_resolved}</strong><span>NAT mappings</span></div>
            <div><strong>{s.policies_eligible}</strong><span>Policies checked</span></div>
            <div><strong>{s.evidence_items}</strong><span>Evidence snippets</span></div>
          </div>
          {review.evidence.length > 0 && (
            <ul className="nrr-snippets">
              {review.evidence.slice(0, 2).map((item) => (
                <li key={item.reference}><strong>{item.reference}</strong> · {item.kind.replace(/_/g, " ")}</li>
              ))}
            </ul>
          )}
          {s.incomplete && <p className="nrr-note">Limited coverage; no absence conclusion is supported.</p>}
        </>
      ) : <p className="nrr-note">Firewall route and NAT review is not applicable to this IDS configuration.</p>}
      <p className="nrr-note">Full source evidence, traffic-path conditions, NAT relationships and recommendations are in the PDF report only.</p>
    </section>
  );
}
