from dataclasses import dataclass
from typing import List, Optional

from app.analyzer.nat_matcher import NATMatcher
from app.analyzer.object_resolver import NetworkObjectResolver
from app.analyzer.object_usage import ObjectUsageAnalyzer
from app.analyzer.rule_matcher import RuleMatcher
from app.analyzer.route_matcher import RouteMatcher
from app.models.firewall import FirewallConfig, NATRule
from app.models.rule import FirewallRule
from app.analyzer.network_matcher import NetworkMatcher
from app.models.firewall import Route
from ipaddress import ip_network


@dataclass
class Finding:
    """Represents a security finding."""

    severity: str
    code: str
    rule_id: Optional[int]
    line_number: Optional[int]
    title: str
    description: str
    recommendation: str
    related_rule_id: Optional[int] = None


class FirewallAnalyzer:
    """
    Main firewall security analysis engine.

    Security checks:

        FW-001  Unrestricted any-to-any permit
        FW-002  Dangerous management services
        FW-003  Missing logging
        FW-004  Shadowed permit rules
        FW-005  Overlapping permit rules
        FW-006  Duplicate firewall rules
        FW-007  Unreachable deny rules
        FW-008  Static NAT exposure
        FW-009  NAT rule shadowing
        FW-010  NAT/ACL consistency
        FW-011  Dangerous service-object exposure
        FW-012  Unused network object
        FW-013  Unused service object
        FW-014  Unreachable/redundant rules
        FW-015  Broad source scope
        FW-016  Broad destination scope
        FW-017  Broad protocol scope
        FW-018  Broad service/port scope
        FW-019  Overlapping NAT rules
        FW-020  Overlapping NAT source translation
        FW-021  Duplicate route
        FW-022  Potentially redundant route
    """

    DANGEROUS_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
    }

    def __init__(
        self,
        firewall: FirewallConfig,
    ):
        self.firewall = firewall

        self.resolver = NetworkObjectResolver(
            firewall
        )

        self.rule_matcher = RuleMatcher(
            self.resolver
        )

        self.nat_matcher = NATMatcher()

        self.route_matcher = RouteMatcher()

        self.object_usage = ObjectUsageAnalyzer(
            firewall
        )
    def _check_overlapping_nat_translations(self) -> List[Finding]:
        """
        Detect NAT rules whose source scopes overlap but whose
        translated sources differ.

        This can indicate ambiguous or order-dependent NAT behavior.

        Exact semantic duplicates are excluded because they are handled
        by the existing NAT shadowing logic.
        """

        findings: List[Finding] = []
        nat_rules = self.firewall.nat_rules

        for current_index, current_nat in enumerate(nat_rules):

            for earlier_index in range(current_index):

                earlier_nat = nat_rules[earlier_index]

                # Exact NAT duplicates are handled separately.
                if self.nat_matcher.shadows(
                    earlier_nat,
                    current_nat,
                ):
                    continue

                # The rules must operate on overlapping traffic.
                if not self.nat_matcher.rules_overlap(
                    earlier_nat,
                    current_nat,
                ):
                    continue

                # The source networks must overlap.
                if not self.nat_matcher._addresses_overlap_with_any(
                    earlier_nat.source,
                    current_nat.source,
                ):
                    continue

                # If translated sources are identical, this is not
                # a conflicting translation target.
                if self.nat_matcher.translated_source_matches(
                    earlier_nat,
                    current_nat,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="MEDIUM",
                        code="FW-020",
                        rule_id=current_nat.id,
                        line_number=current_nat.line_number,
                        title="Overlapping NAT source translation",
                        description=(
                            f"NAT rule {current_nat.id} has a source "
                            f"scope that overlaps earlier NAT rule "
                            f"{earlier_nat.id}, but the rules use "
                            "different translated source addresses."
                        ),
                        recommendation=(
                            "Review the NAT rule order and source "
                            "translation scope. Restrict overlapping "
                            "source networks or make the intended "
                            "translation behavior explicit."
                        ),
                        related_rule_id=earlier_nat.id,
                    )
                )

                break

        return findings
    
    def _check_overlapping_nat_rules(self) -> List[Finding]:
        
        findings: List[Finding] = []
        nat_rules = self.firewall.nat_rules

        for current_index, current_nat in enumerate(nat_rules):

            for earlier_index in range(current_index):

                earlier_nat = nat_rules[earlier_index]

                # Exact semantic duplicates are handled separately.
                if self.nat_matcher.shadows(
                    earlier_nat,
                    current_nat,
                ):
                    continue

                if not self.nat_matcher.rules_overlap(
                    earlier_nat,
                    current_nat,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="MEDIUM",
                        code="FW-019",
                        rule_id=current_nat.id,
                        line_number=current_nat.line_number,
                        title="Overlapping NAT rules",
                        description=(
                            f"NAT rule {current_nat.id} overlaps "
                            f"with earlier NAT rule "
                            f"{earlier_nat.id}. The two rules "
                            "match overlapping traffic scopes."
                        ),
                        recommendation=(
                            "Review the NAT rule order and restrict "
                            "the overlapping rules so that each NAT "
                            "rule matches a clearly defined traffic "
                            "scope."
                        ),
                        related_rule_id=earlier_nat.id,
                    )
                )

                break

        return findings

    def analyze(self) -> List[Finding]:
        """Run all security checks."""

        findings: List[Finding] = []

        findings.extend(
            self._check_unrestricted_rules()
        )

        findings.extend(
            self._check_dangerous_ports()
        )

        findings.extend(
            self._check_missing_logging()
        )

        findings.extend(
            self._check_shadowed_rules()
        )

        findings.extend(
            self._check_overlapping_rules()
        )

        findings.extend(
            self._check_duplicate_rules()
        )

        findings.extend(
            self._check_unreachable_denies()
        )

        findings.extend(
            self._check_static_nat_exposure()
        )

        findings.extend(
            self._check_nat_shadowing()
        )

        findings.extend(
            self._check_nat_acl_consistency()
        )

        findings.extend(
            self._check_dangerous_service_objects()
        )

        findings.extend(
            self._check_unused_network_objects()
        )

        findings.extend(
            self._check_unused_service_objects()
        )

        findings.extend(
            self._check_unreachable_redundant_rules()
        )

        findings.extend(
            self._check_broad_source_scope()
        )

        findings.extend(
            self._check_broad_destination_scope()
        )

        findings.extend(self._check_broad_protocol_scope()
        )

        findings.extend(
            self._check_broad_service_scope()
        )

        findings.extend(
            self._check_overlapping_nat_rules()
        )

        findings.extend(self._check_overlapping_nat_translations())

        findings.extend(self._check_duplicate_routes())

        findings.extend(self._check_redundant_routes())

        findings.extend(self._check_conflicting_routes())

        findings.extend(self._check_missing_default_route())

        findings.extend(self._check_invalid_route_next_hop())

        findings.extend(self._check_route_next_hop_family_mismatch())

        
        return findings

    def calculate_security_score(
        self,
        findings: List[Finding],
    ) -> int:
        """
        Calculate an analyzer-level security score.

        The report generator calculates the final report score.
        This method remains available for callers that want a
        quick engine-level score.
        """

        critical = sum(
            1
            for finding in findings
            if finding.severity.upper() == "CRITICAL"
        )

        high = sum(
            1
            for finding in findings
            if finding.severity.upper() == "HIGH"
        )

        medium = sum(
            1
            for finding in findings
            if finding.severity.upper() == "MEDIUM"
        )

        low = sum(
            1
            for finding in findings
            if finding.severity.upper() == "LOW"
        )

        penalty = (
            (critical * 30)
            + (high * 10)
            + (medium * 3)
            + low
        )

        return max(
            0,
            min(
                100,
                100 - penalty,
            ),
        )

    # ================================================================
    # FW-001
    # ================================================================

    def _check_unrestricted_rules(
        self,
    ) -> List[Finding]:
        """Detect genuinely unrestricted permit rules."""

        findings: List[Finding] = []

        for rule in self.firewall.rules:

            if rule.disabled:
                continue

            if not rule.is_permit():
                continue

            if not self._is_unrestricted_permit(
                rule
            ):
                continue

            findings.append(
                Finding(
                    severity="CRITICAL",
                    code="FW-001",
                    rule_id=rule.id,
                    line_number=rule.line_number,
                    title="Any-to-any permit rule",
                    description=(
                        "This rule permits unrestricted traffic "
                        "from any source to any destination."
                    ),
                    recommendation=(
                        "Restrict the source, destination, "
                        "protocol, and service to only what "
                        "is required."
                    ),
                )
            )

        return findings

    # ================================================================
    # FW-002
    # ================================================================

    def _check_dangerous_ports(
        self,
    ) -> List[Finding]:
        """Detect permits exposing dangerous service ports."""

        findings: List[Finding] = []

        for rule in self.firewall.rules:

            if rule.disabled:
                continue

            if not rule.is_permit():
                continue

            for port in set(
                rule.destination_ports
            ):

                service_name = self.DANGEROUS_PORTS.get(
                    port
                )

                if service_name is None:
                    continue

                if service_name == "SSH":
                    recommendation = (
                        "Restrict SSH access to trusted "
                        "management networks and avoid "
                        "unnecessary Internet exposure."
                    )

                elif service_name == "RDP":
                    recommendation = (
                        "Restrict RDP access to trusted "
                        "networks and prefer VPN or another "
                        "controlled remote-access method."
                    )

                else:
                    recommendation = (
                        f"Restrict {service_name} access "
                        "to trusted networks and remove "
                        "unnecessary exposure."
                    )

                findings.append(
                    Finding(
                        severity="HIGH",
                        code="FW-002",
                        rule_id=rule.id,
                        line_number=rule.line_number,
                        title=(
                            f"Potentially exposed "
                            f"{service_name} service"
                        ),
                        description=(
                            f"The rule permits "
                            f"{service_name} traffic "
                            f"on port {port}."
                        ),
                        recommendation=recommendation,
                    )
                )

        return findings

    # ================================================================
    # FW-003
    # ================================================================

    def _check_missing_logging(
        self,
    ) -> List[Finding]:
        """Detect rules without logging."""

        findings: List[Finding] = []

        for rule in self.firewall.rules:

            if rule.disabled:
                continue

            if rule.logging:
                continue

            findings.append(
                Finding(
                    severity="LOW",
                    code="FW-003",
                    rule_id=rule.id,
                    line_number=rule.line_number,
                    title="Rule has no logging",
                    description=(
                        "This firewall rule does not have "
                        "logging enabled."
                    ),
                    recommendation=(
                        "Enable logging where appropriate "
                        "so traffic can be monitored and "
                        "investigated."
                    ),
                )
            )

        return findings

    # ================================================================
    # FW-004
    # ================================================================

    def _check_shadowed_rules(
        self,
    ) -> List[Finding]:
        """
        Detect permit rules completely covered by an earlier
        permit rule in the same ACL.

        An unrestricted permit ip any any rule is excluded
        because it is already reported by FW-001.
        """

        findings: List[Finding] = []

        rules = self.firewall.rules

        for current_index, current_rule in enumerate(
            rules
        ):

            if current_rule.disabled:
                continue

            if not current_rule.is_permit():
                continue

            for earlier_index in range(
                current_index
            ):

                earlier_rule = rules[
                    earlier_index
                ]

                if earlier_rule.disabled:
                    continue

                if not earlier_rule.is_permit():
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if self._is_unrestricted_permit(
                    earlier_rule
                ):
                    continue

                if self.rule_matcher.rules_equal(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if not self.rule_matcher.matches_contained_by(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="MEDIUM",
                        code="FW-004",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title=(
                            "Permit rule is shadowed "
                            "by an earlier permit"
                        ),
                        description=(
                            f"Rule {current_rule.id} is "
                            f"completely covered by earlier "
                            f"permit rule {earlier_rule.id}."
                        ),
                        recommendation=(
                            "Review the later rule and remove "
                            "it if it is redundant."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    # ================================================================
    # FW-005
    # ================================================================

    def _check_overlapping_rules(
        self,
    ) -> List[Finding]:
        """
        Detect meaningful overlapping permit rules.

        FW-005 is intended for partial/meaningful overlap.

        Full containment belongs to FW-004, while exact
        duplicates belong to FW-006.

        Important:
        containment is checked in BOTH directions. This matters
        when a rule contains multiple address networks. A rule
        can partially overlap another rule without the complete
        multi-network rule being contained by the other rule.
        """

        findings: List[Finding] = []

        rules = self.firewall.rules

        for current_index, current_rule in enumerate(
            rules
        ):

            if current_rule.disabled:
                continue

            if not current_rule.is_permit():
                continue

            for earlier_index in range(
                current_index
            ):

                earlier_rule = rules[
                    earlier_index
                ]

                if earlier_rule.disabled:
                    continue

                if not earlier_rule.is_permit():
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if self._is_unrestricted_permit(
                    earlier_rule
                ):
                    continue

                if self._is_unrestricted_permit(
                    current_rule
                ):
                    continue

                if self.rule_matcher.rules_equal(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if self.rule_matcher.matches_contained_by(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if self.rule_matcher.matches_contained_by(
                    current_rule,
                    earlier_rule,
                ):
                    continue

                if not self.rule_matcher.rules_overlap(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="MEDIUM",
                        code="FW-005",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="Overlapping permit rules",
                        description=(
                            f"Rule {current_rule.id} overlaps "
                            f"with earlier permit rule "
                            f"{earlier_rule.id}."
                        ),
                        recommendation=(
                            "Review both rules to ensure "
                            "their overlapping traffic is "
                            "intentional."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    # ================================================================
    # FW-006
    # ================================================================

    def _check_duplicate_rules(
        self,
    ) -> List[Finding]:
        """Detect exact duplicate rules."""

        findings: List[Finding] = []

        rules = self.firewall.rules

        for current_index, current_rule in enumerate(
            rules
        ):

            if current_rule.disabled:
                continue

            for earlier_index in range(
                current_index
            ):

                earlier_rule = rules[
                    earlier_index
                ]

                if earlier_rule.disabled:
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if not self.rule_matcher.rules_equal(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-006",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="Duplicate firewall rule",
                        description=(
                            f"Rule {current_rule.id} is an "
                            f"exact duplicate of earlier "
                            f"rule {earlier_rule.id}."
                        ),
                        recommendation=(
                            "Remove the duplicate rule unless "
                            "there is a documented reason "
                            "to keep it."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    # ================================================================
    # FW-007
    # ================================================================

    def _check_unreachable_denies(
        self,
    ) -> List[Finding]:
        """
        Detect deny rules completely covered by an earlier
        permit rule in the same ACL.
        """

        findings: List[Finding] = []

        rules = self.firewall.rules

        for current_index, current_rule in enumerate(
            rules
        ):

            if current_rule.disabled:
                continue

            if not current_rule.is_deny():
                continue

            for earlier_index in range(
                current_index
            ):

                earlier_rule = rules[
                    earlier_index
                ]

                if earlier_rule.disabled:
                    continue

                if not earlier_rule.is_permit():
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if not self.rule_matcher.matches_contained_by(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="HIGH",
                        code="FW-007",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="Unreachable deny rule",
                        description=(
                            f"Rule {current_rule.id} is "
                            f"completely covered by earlier "
                            f"permit rule {earlier_rule.id}."
                        ),
                        recommendation=(
                            "Review the rule order. If the "
                            "deny is intended to block traffic, "
                            "move it before the broader permit rule."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    # ================================================================
    # FW-008
    # ================================================================

    def _check_static_nat_exposure(
        self,
    ) -> List[Finding]:
        """Detect static NAT translations."""

        findings: List[Finding] = []

        for nat_rule in self.firewall.nat_rules:

            translated = (
                nat_rule.translated_source or ""
            ).strip()

            if not translated:
                continue

            if translated.lower().startswith(
                "interface:"
            ):
                continue

            findings.append(
                Finding(
                    severity="MEDIUM",
                    code="FW-008",
                    rule_id=nat_rule.id,
                    line_number=nat_rule.line_number,
                    title="Potentially exposed static NAT",
                    description=(
                        f"Internal resource "
                        f"{nat_rule.source} is statically "
                        f"translated to {translated}."
                    ),
                    recommendation=(
                        "Verify that the static NAT is required "
                        "and ensure associated access-control "
                        "policy restricts access appropriately."
                    ),
                )
            )

        return findings

    # ================================================================
    # FW-009
    # ================================================================

    def _check_nat_shadowing(
        self,
    ) -> List[Finding]:
        """Detect NAT rules shadowed by earlier NAT rules."""

        findings: List[Finding] = []

        nat_rules = self.firewall.nat_rules

        for current_index, current_rule in enumerate(
            nat_rules
        ):

            for earlier_index in range(
                current_index
            ):

                earlier_rule = nat_rules[
                    earlier_index
                ]

                if not self.nat_matcher.shadows(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="MEDIUM",
                        code="FW-009",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="NAT rule is shadowed",
                        description=(
                            f"NAT rule {current_rule.id} "
                            f"is completely shadowed by "
                            f"earlier NAT rule "
                            f"{earlier_rule.id}."
                        ),
                        recommendation=(
                            "Review the NAT rule order and "
                            "remove the later rule if it "
                            "is redundant."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    # ================================================================
    # FW-010
    # ================================================================

    def _check_nat_acl_consistency(
        self,
    ) -> List[Finding]:
        """
        Correlate static NAT translations with ACL permit rules.

        A translated public address is compared against the
        destination scope of permit rules.
        """

        findings: List[Finding] = []

        for nat_rule in self.firewall.nat_rules:

            translated = (
                nat_rule.translated_source or ""
            ).strip()

            if not translated:
                continue

            if translated.lower().startswith(
                "interface:"
            ):
                continue

            matching_permits = []

            for firewall_rule in self.firewall.rules:

                if firewall_rule.disabled:
                    continue

                if not firewall_rule.is_permit():
                    continue

                if not self._nat_rule_applies_to_acl(
                    nat_rule,
                    firewall_rule,
                ):
                    continue

                if not self.nat_matcher.translated_address_matches_rule(
                    nat_rule,
                    firewall_rule,
                ):
                    continue

                matching_permits.append(
                    firewall_rule
                )

            if matching_permits:

                first_match = matching_permits[0]

                findings.append(
                    Finding(
                        severity="HIGH",
                        code="FW-010",
                        rule_id=nat_rule.id,
                        line_number=nat_rule.line_number,
                        title="Static NAT has matching permit ACL",
                        description=(
                            f"Static NAT translation "
                            f"{translated} has a matching "
                            f"permit rule {first_match.id} "
                            f"that includes the translated "
                            f"address in its destination."
                        ),
                        recommendation=(
                            "Verify that the permit rule is "
                            "intentionally exposing the NAT "
                            "resource and restrict source, "
                            "destination, protocol, and ports "
                            "to the minimum required access."
                        ),
                        related_rule_id=first_match.id,
                    )
                )

            else:

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-010",
                        rule_id=nat_rule.id,
                        line_number=nat_rule.line_number,
                        title="Static NAT has no matching permit ACL",
                        description=(
                            f"Static NAT translation "
                            f"{translated} does not have a "
                            f"matching permit rule whose "
                            f"destination includes the "
                            f"translated address."
                        ),
                        recommendation=(
                            "Verify that the NAT resource is "
                            "intentionally reachable. If access "
                            "is required, create a narrowly "
                            "scoped ACL permitting only the "
                            "required traffic."
                        ),
                    )
                )

        return findings

    # ================================================================
    # FW-011
    # ================================================================

    def _check_dangerous_service_objects(
        self,
    ) -> List[Finding]:
        """Detect dangerous ports exposed through service objects."""

        findings: List[Finding] = []

        for rule in self.firewall.rules:

            if rule.disabled:
                continue

            if not rule.is_permit():
                continue

            service_names = set()

            service_names.update(
                rule.source_services
            )

            service_names.update(
                rule.destination_services
            )

            for service_name in service_names:

                service = self._find_service(
                    service_name
                )

                if service is None:
                    continue

                for port in service.ports:

                    if port not in self.DANGEROUS_PORTS:
                        continue

                    service_label = (
                        self.DANGEROUS_PORTS[port]
                    )

                    findings.append(
                        Finding(
                            severity="HIGH",
                            code="FW-011",
                            rule_id=rule.id,
                            line_number=rule.line_number,
                            title=(
                                "Dangerous service-object exposure"
                            ),
                            description=(
                                f"Rule {rule.id} uses service "
                                f"object {service.name}, which "
                                f"permits {service_label} traffic "
                                f"on port {port}."
                            ),
                            recommendation=(
                                f"Restrict {service_label} "
                                "access to trusted networks "
                                "and remove unnecessary "
                                "service-object exposure."
                            ),
                        )
                    )

        return findings

    # ================================================================
    # FW-012
    # ================================================================

    def _check_unused_network_objects(
        self,
    ) -> List[Finding]:
        """
        Detect network objects that are not referenced by the
        active firewall configuration.

        Object-group dependencies are resolved recursively,
        including nested object-groups.
        """

        findings: List[Finding] = []

        if not self.firewall.networks:
            return findings

        used_objects = (
            self.object_usage.used_network_objects()
        )

        for object_name, network_object in (
            self.firewall.networks.items()
        ):

            normalized_name = (
                object_name.strip().lower()
            )

            if normalized_name in used_objects:
                continue

            findings.append(
                Finding(
                    severity="LOW",
                    code="FW-012",
                    rule_id=None,
                    line_number=network_object.line_number,
                    title="Unused network object",
                    description=(
                        f"Network object {object_name} is not "
                        "referenced by any active ACL, NAT rule, "
                        "or network object-group."
                    ),
                    recommendation=(
                        "Verify that the object is no longer "
                        "required and remove it if it is obsolete."
                    ),
                )
            )

        return findings

    # ================================================================
    # FW-013
    # ================================================================

    def _check_unused_service_objects(
        self,
    ) -> List[Finding]:
        """
        Detect service objects that are not referenced by any
        active firewall rule.
        """

        findings: List[Finding] = []

        if not self.firewall.services:
            return findings

        used_services = (
            self.object_usage.used_service_objects()
        )

        for service_name, service in (
            self.firewall.services.items()
        ):

            normalized_name = (
                service_name.strip().lower()
            )

            if normalized_name in used_services:
                continue

            findings.append(
                Finding(
                    severity="LOW",
                    code="FW-013",
                    rule_id=None,
                    line_number=service.line_number,
                    title="Unused service object",
                    description=(
                        f"Service object {service_name} is not "
                        "referenced by any active firewall rule."
                    ),
                    recommendation=(
                        "Verify that the service object is no "
                        "longer required and remove it if it "
                        "is obsolete."
                    ),
                )
            )

        return findings

    # ================================================================
    # FW-014
    # ================================================================

    def _check_unreachable_redundant_rules(
        self,
    ) -> List[Finding]:
        """
        Detect later rules that are completely covered by an
        earlier deny rule.

        Existing checks already handle:

            FW-004  earlier permit -> later permit
            FW-006  exact duplicate
            FW-007  earlier permit -> later deny

        FW-014 handles the remaining deny-first cases:

            earlier deny -> later deny
            earlier deny -> later permit
        """

        findings: List[Finding] = []
        rules = self.firewall.rules

        for current_index, current_rule in enumerate(rules):
            if current_rule.disabled:
                continue

            for earlier_index in range(current_index):
                earlier_rule = rules[earlier_index]

                if earlier_rule.disabled:
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if not earlier_rule.is_deny():
                    continue

                if not (
                    current_rule.is_deny()
                    or current_rule.is_permit()
                ):
                    continue

                if self.rule_matcher.rules_equal(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if not self.rule_matcher.matches_contained_by(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                if current_rule.is_permit():
                    title = (
                        "Permit rule is unreachable"
                    )

                    description = (
                        f"Rule {current_rule.id} is completely "
                        f"covered by earlier deny rule "
                        f"{earlier_rule.id}. The traffic matched "
                        "by this permit rule will already have "
                        "been denied."
                    )

                    recommendation = (
                        "Review the rule order. If the permit "
                        "is required, move it before the broader "
                        "deny rule or narrow the deny scope."
                    )

                else:
                    title = (
                        "Deny rule is redundant"
                    )

                    description = (
                        f"Rule {current_rule.id} is completely "
                        f"covered by earlier deny rule "
                        f"{earlier_rule.id}. The later deny "
                        "does not add additional blocking scope."
                    )

                    recommendation = (
                        "Remove the redundant deny rule unless "
                        "there is a documented reason to retain it."
                    )

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-014",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title=title,
                        description=description,
                        recommendation=recommendation,
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

       
    # ================================================================
    # FW-015
    # ================================================================

    def _check_broad_source_scope(self) -> List[Finding]:
        """
        Detect permit rules whose source scope is broader than an
        earlier permit rule with the same destination, protocol,
        and destination ports.
        """

        findings: List[Finding] = []
        rules = self.firewall.rules

        for current_index, current_rule in enumerate(rules):

            if current_rule.disabled:
                continue

            if not current_rule.is_permit():
                continue

            # FW-001 already handles completely unrestricted
            # any-to-any permits.
            if (
                current_rule.is_any_source()
                and current_rule.is_any_destination()
            ):
                continue

            for earlier_index in range(current_index):

                earlier_rule = rules[earlier_index]

                if earlier_rule.disabled:
                    continue

                if not earlier_rule.is_permit():
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                # Destination must be identical.
                if not self.rule_matcher._addresses_equal(
                    earlier_rule.destination,
                    current_rule.destination,
                ):
                    continue

                # Protocol must be identical.
                if not self.rule_matcher._protocols_equal(
                    earlier_rule.protocol,
                    current_rule.protocol,
                ):
                    continue

                # Destination ports must be identical.
                if not self.rule_matcher._ports_equal(
                    earlier_rule.destination_ports,
                    current_rule.destination_ports,
                ):
                    continue

                # Current source must be strictly broader.
                if not self._source_scope_is_broader(
                    current_rule,
                    earlier_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-015",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="Broad source scope",
                        description=(
                            f"Rule {current_rule.id} permits traffic "
                            f"from a broader source scope than earlier "
                            f"rule {earlier_rule.id}, while matching "
                            "the same destination, protocol, and "
                            "destination ports."
                        ),
                        recommendation=(
                            "Restrict the source to the smallest "
                            "network or set of networks required "
                            "for this rule."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    def _source_scope_is_broader(
        self,
        broader_rule: FirewallRule,
        narrower_rule: FirewallRule,
    ) -> bool:
        """
        Return True when broader_rule has a strictly broader source
        scope than narrower_rule.
        """

        broader_any = self.resolver.is_any(
            broader_rule.source
        )

        narrower_any = self.resolver.is_any(
            narrower_rule.source
        )

        # "any" is broader than every concrete source.
        if broader_any:
            return not narrower_any

        # A concrete source cannot be broader than "any".
        if narrower_any:
            return False

        broader_networks = self.resolver.resolve_list(
            broader_rule.source
        )

        narrower_networks = self.resolver.resolve_list(
            narrower_rule.source
        )

        if not broader_networks or not narrower_networks:
            return False

        if not NetworkMatcher.contains(
            broader_networks,
            narrower_networks,
        ):
            return False

        if NetworkMatcher.equal(
            broader_networks,
            narrower_networks,
        ):
            return False

        return True

        # ================================================================
    # FW-016
    # ================================================================

    def _check_broad_destination_scope(self) -> List[Finding]:
        """
        Detect permit rules whose destination scope is broader than
        an earlier permit rule with the same source, protocol, and
        destination ports.
        """

        findings: List[Finding] = []
        rules = self.firewall.rules

        for current_index, current_rule in enumerate(rules):

            if current_rule.disabled:
                continue

            if not current_rule.is_permit():
                continue

            # FW-001 already handles completely unrestricted
            # any-to-any permits.
            if (
                current_rule.is_any_source()
                and current_rule.is_any_destination()
            ):
                continue

            for earlier_index in range(current_index):

                earlier_rule = rules[earlier_index]

                if earlier_rule.disabled:
                    continue

                if not earlier_rule.is_permit():
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                # Source must be identical.
                if not self.rule_matcher._addresses_equal(
                    earlier_rule.source,
                    current_rule.source,
                ):
                    continue

                # Protocol must be identical.
                if not self.rule_matcher._protocols_equal(
                    earlier_rule.protocol,
                    current_rule.protocol,
                ):
                    continue

                # Destination ports must be identical.
                if not self.rule_matcher._ports_equal(
                    earlier_rule.destination_ports,
                    current_rule.destination_ports,
                ):
                    continue

                # Current destination must be strictly broader.
                if not self._destination_scope_is_broader(
                    current_rule,
                    earlier_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-016",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="Broad destination scope",
                        description=(
                            f"Rule {current_rule.id} permits traffic "
                            f"to a broader destination scope than "
                            f"earlier rule {earlier_rule.id}, while "
                            "matching the same source, protocol, and "
                            "destination ports."
                        ),
                        recommendation=(
                            "Restrict the destination to the smallest "
                            "network or set of networks required "
                            "for this rule."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    def _destination_scope_is_broader(
        self,
        broader_rule: FirewallRule,
        narrower_rule: FirewallRule,
    ) -> bool:
        """
        Return True when broader_rule has a strictly broader
        destination scope than narrower_rule.
        """

        broader_any = self.resolver.is_any(
            broader_rule.destination
        )

        narrower_any = self.resolver.is_any(
            narrower_rule.destination
        )

        # "any" is broader than every concrete destination.
        if broader_any:
            return not narrower_any

        # A concrete destination cannot be broader than "any".
        if narrower_any:
            return False

        broader_networks = self.resolver.resolve_list(
            broader_rule.destination
        )

        narrower_networks = self.resolver.resolve_list(
            narrower_rule.destination
        )

        if not broader_networks or not narrower_networks:
            return False

        if not NetworkMatcher.contains(
            broader_networks,
            narrower_networks,
        ):
            return False

        if NetworkMatcher.equal(
            broader_networks,
            narrower_networks,
        ):
            return False

        return True

        # ================================================================
    # FW-017
    # ================================================================

    def _check_broad_protocol_scope(self) -> List[Finding]:
        """
        Detect permit rules whose protocol scope is broader than
        an earlier permit rule with the same source, destination,
        and destination ports.
        """

        findings: List[Finding] = []
        rules = self.firewall.rules

        for current_index, current_rule in enumerate(rules):

            if current_rule.disabled:
                continue

            if not current_rule.is_permit():
                continue

            # FW-001 already handles completely unrestricted
            # any-to-any permits.
            if (
                current_rule.is_any_source()
                and current_rule.is_any_destination()
            ):
                continue

            for earlier_index in range(current_index):

                earlier_rule = rules[earlier_index]

                if earlier_rule.disabled:
                    continue

                if not earlier_rule.is_permit():
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                # Source must be identical.
                if not self.rule_matcher._addresses_equal(
                    earlier_rule.source,
                    current_rule.source,
                ):
                    continue

                # Destination must be identical.
                if not self.rule_matcher._addresses_equal(
                    earlier_rule.destination,
                    current_rule.destination,
                ):
                    continue

                # Destination ports must be identical.
                if not self.rule_matcher._ports_equal(
                    earlier_rule.destination_ports,
                    current_rule.destination_ports,
                ):
                    continue

                # Current protocol must be strictly broader.
                if not self._protocol_scope_is_broader(
                    current_rule,
                    earlier_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-017",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="Broad protocol scope",
                        description=(
                            f"Rule {current_rule.id} permits traffic "
                            f"using a broader protocol scope than "
                            f"earlier rule {earlier_rule.id}, while "
                            "matching the same source, destination, "
                            "and destination ports."
                        ),
                        recommendation=(
                            "Restrict the protocol to the smallest "
                            "protocol scope required for this rule."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    def _protocol_scope_is_broader(
        self,
        broader_rule: FirewallRule,
        narrower_rule: FirewallRule,
    ) -> bool:
        """
        Return True when broader_rule has a strictly broader
        protocol scope than narrower_rule.

        Cisco ASA uses "ip" to represent any IP protocol.
        Therefore:

            ip > tcp
            ip > udp

        while:

            tcp == tcp
            udp == udp
            tcp != udp
        """

        broader_protocol = (
            broader_rule.protocol or ""
        ).strip().lower()

        narrower_protocol = (
            narrower_rule.protocol or ""
        ).strip().lower()

        # Empty protocol values cannot safely be treated as broad.
        if not broader_protocol or not narrower_protocol:
            return False

        # "ip" represents any IP protocol.
        if broader_protocol == "ip":
            return narrower_protocol != "ip"

        # A specific protocol cannot be broader than "ip".
        if narrower_protocol == "ip":
            return False

        # Different concrete protocols are not broader/narrower.
        return False

        # ================================================================
    # FW-018
    # ================================================================

    def _check_broad_service_scope(self) -> List[Finding]:
        """
        Detect permit rules whose destination-port scope is broader
        than an earlier permit rule with the same source,
        destination, and protocol.
        """

        findings: List[Finding] = []
        rules = self.firewall.rules

        for current_index, current_rule in enumerate(rules):

            if current_rule.disabled:
                continue

            if not current_rule.is_permit():
                continue

            # FW-001 already handles completely unrestricted
            # any-to-any permits.
            if (
                current_rule.is_any_source()
                and current_rule.is_any_destination()
            ):
                continue

            for earlier_index in range(current_index):

                earlier_rule = rules[earlier_index]

                if earlier_rule.disabled:
                    continue

                if not earlier_rule.is_permit():
                    continue

                if not self._same_acl(
                    earlier_rule,
                    current_rule,
                ):
                    continue

                # Source must be identical.
                if not self.rule_matcher._addresses_equal(
                    earlier_rule.source,
                    current_rule.source,
                ):
                    continue

                # Destination must be identical.
                if not self.rule_matcher._addresses_equal(
                    earlier_rule.destination,
                    current_rule.destination,
                ):
                    continue

                # Protocol must be identical.
                if not self.rule_matcher._protocols_equal(
                    earlier_rule.protocol,
                    current_rule.protocol,
                ):
                    continue

                # Current service/port scope must be strictly broader.
                if not self._service_scope_is_broader(
                    current_rule,
                    earlier_rule,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-018",
                        rule_id=current_rule.id,
                        line_number=current_rule.line_number,
                        title="Broad service/port scope",
                        description=(
                            f"Rule {current_rule.id} permits traffic "
                            f"using a broader service/port scope than "
                            f"earlier rule {earlier_rule.id}, while "
                            "matching the same source, destination, "
                            "and protocol."
                        ),
                        recommendation=(
                            "Restrict the service or destination ports "
                            "to the smallest set required for this rule."
                        ),
                        related_rule_id=earlier_rule.id,
                    )
                )

                break

        return findings

    def _service_scope_is_broader(
        self,
        broader_rule: FirewallRule,
        narrower_rule: FirewallRule,
    ) -> bool:
        """
        Return True when broader_rule has a strictly broader
        destination-port scope than narrower_rule.

        An empty destination-port list is treated as unrestricted
        service/port scope.

        Examples:

            [] > [443]
            [80, 443] > [443]

        while:

            [443] == [443]
            [443] is not broader than [80, 443]
        """

        broader_ports = set(
            broader_rule.destination_ports
        )

        narrower_ports = set(
            narrower_rule.destination_ports
        )

        # Empty port scope represents unrestricted ports.
        if not broader_ports:
            return bool(narrower_ports)

        # A restricted port set cannot be broader than unrestricted.
        if not narrower_ports:
            return False

        # Every narrower port must be contained by the broader scope.
        if not narrower_ports.issubset(broader_ports):
            return False

        # Equal scopes are not broader.
        if broader_ports == narrower_ports:
            return False

        return True
    
    # ================================================================
    # FW-021
    # ================================================================

    def _check_duplicate_routes(self) -> List[Finding]:
        """
        Detect duplicate routing entries.

        A route is considered a duplicate when an earlier route has the
        same destination, next hop, and interface. Metric differences are
        intentionally ignored because the route still represents the same
        forwarding path.
        """
        findings: List[Finding] = []
        routes = self.firewall.routes

        for current_index, current_route in enumerate(routes):
            for earlier_index in range(current_index):
                earlier_route = routes[earlier_index]

                if not self.route_matcher.routes_are_duplicates(
                    earlier_route,
                    current_route,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-021",
                        rule_id=None,
                        line_number=current_route.line_number,
                        title="Duplicate route",
                        description=(
                            f"Route at line {current_route.line_number} "
                            f"duplicates the earlier route at line "
                            f"{earlier_route.line_number}. Both routes use "
                            f"destination {current_route.destination}, next "
                            f"hop {current_route.next_hop}, and interface "
                            f"{current_route.interface}."
                        ),
                        recommendation=(
                            "Remove the duplicate route unless it is "
                            "required by a configuration-generation or "
                            "operational process."
                        ),
                        related_rule_id=None,
                    )
                )
                break

        return findings

    # ================================================================
    # FW-022
    # ================================================================

    def _check_redundant_routes(self) -> List[Finding]:
        """
        Detect later routes that are completely covered by an earlier
        broader route using the same forwarding path.

        The more-specific route is reported as potentially redundant only
        when the earlier broader route uses the same next hop and interface.
        Routes with different forwarding paths are intentionally not reported
        because a more-specific route may be intentional.
        """
        findings: List[Finding] = []
        routes = self.firewall.routes

        for current_index, current_route in enumerate(routes):
            for earlier_index in range(current_index):
                earlier_route = routes[earlier_index]

                if self.route_matcher.routes_are_duplicates(
                    earlier_route,
                    current_route,
                ):
                    continue

                if not self.route_matcher.is_more_specific(
                    current_route.destination,
                    earlier_route.destination,
                ):
                    continue

                if not self.route_matcher.same_next_hop(
                    earlier_route.next_hop,
                    current_route.next_hop,
                ):
                    continue

                if not self.route_matcher.same_interface(
                    earlier_route.interface,
                    current_route.interface,
                ):
                    continue

                findings.append(
                    Finding(
                        severity="LOW",
                        code="FW-022",
                        rule_id=None,
                        line_number=current_route.line_number,
                        title="Potentially redundant route",
                        description=(
                            f"Route at line {current_route.line_number} "
                            f"({current_route.destination}) is more specific "
                            f"than earlier route at line "
                            f"{earlier_route.line_number} "
                            f"({earlier_route.destination}), but both use "
                            f"the same next hop {current_route.next_hop} and "
                            f"interface {current_route.interface}."
                        ),
                        recommendation=(
                            "Review whether the more-specific route is "
                            "necessary. Remove it if the broader route "
                            "already provides the intended forwarding "
                            "behavior."
                        ),
                        related_rule_id=None,
                    )
                )
                break

        return findings

    def _check_conflicting_routes(self) -> List[Finding]:
        """
        Detect potentially conflicting routes.

        A conflict exists when:
            - an earlier route covers a later, more-specific route
            - the routes use different next hops or interfaces

        This is reported as a review finding rather than a definite
        configuration error because more-specific routes with different
        forwarding paths are often intentional.
        """
        findings: List[Finding] = []
        routes = self.firewall.routes

        for current_index, current_route in enumerate(routes):
            for earlier_index in range(current_index):
                earlier_route = routes[earlier_index]

                # Exact duplicates are handled by FW-021.
                if self.route_matcher.routes_are_duplicates(
                    earlier_route,
                    current_route,
                ):
                    continue

                # We only care about a later route that is more specific
                # than an earlier broader route.
                if not self.route_matcher.is_more_specific(
                    current_route.destination,
                    earlier_route.destination,
                ):
                    continue

                same_next_hop = self.route_matcher.same_next_hop(
                    earlier_route.next_hop,
                    current_route.next_hop,
                )

                same_interface = self.route_matcher.same_interface(
                    earlier_route.interface,
                    current_route.interface,
                )

                # Same forwarding path is handled by FW-022.
                if same_next_hop and same_interface:
                    continue

                differences = []

                if not same_next_hop:
                    differences.append(
                        f"next hop {earlier_route.next_hop} vs "
                        f"{current_route.next_hop}"
                    )

                if not same_interface:
                    differences.append(
                        f"interface {earlier_route.interface} vs "
                        f"{current_route.interface}"
                    )

                difference_text = "; ".join(differences)

                findings.append(
                    Finding(
                        severity="MEDIUM",
                        code="FW-023",
                        rule_id=None,
                        line_number=current_route.line_number,
                        title="Potentially conflicting route",
                        description=(
                            f"Route at line "
                            f"{current_route.line_number} "
                            f"({current_route.destination}) is more "
                            f"specific than earlier route at line "
                            f"{earlier_route.line_number} "
                            f"({earlier_route.destination}), but the "
                            f"forwarding paths differ: "
                            f"{difference_text}."
                        ),
                        recommendation=(
                            "Review whether the more-specific route "
                            "is intentionally overriding the broader "
                            "route. Confirm that the different "
                            "forwarding path is required."
                        ),
                        related_rule_id=None,
                    )
                )

                # Only report the first earlier route that explains
                # the conflict.
                break

        return findings


    def _check_missing_default_route(self) -> List[Finding]:
        """
        Detect when routing configuration exists but no IPv4 default
        route is configured.

        An empty route table is not reported because the analyzer
        cannot determine whether routing is intentionally omitted,
        supplied dynamically, or simply outside the configuration
        being analyzed.
        """
        routes = self.firewall.routes

        # Do not report missing default routes when there is no
        # routing configuration to analyze.
        if not routes:
            return []

        has_ipv4_route = False

        for route in routes:
            network = self.route_matcher.parse_network(
                route.destination
            )

            if network is None:
                continue

            if network.version != 4:
                continue

            has_ipv4_route = True

            if network.prefixlen == 0:
                return []

        # IPv6-only and invalid-only routing tables do not establish
        # that IPv4 routing is configured.
        if not has_ipv4_route:
            return []

        return [
            Finding(
                severity="MEDIUM",
                code="FW-024",
                rule_id=None,
                line_number=None,
                title="Missing IPv4 default route",
                description=(
                    "The firewall contains routing configuration "
                    "but does not have an IPv4 default route "
                    "(0.0.0.0/0). Traffic destined for networks "
                    "without a more-specific route may have no "
                    "valid forwarding path."
                ),
                recommendation=(
                    "Review the routing design and add an IPv4 "
                    "default route if this firewall is expected "
                    "to forward traffic for destinations that are "
                    "not covered by more-specific routes."
                ),
                related_rule_id=None,
            )
        ]
        # ================================================================
    # FW-025: Invalid route next-hop address
    # ================================================================

    def _check_invalid_route_next_hop(self) -> List[Finding]:
        """
        Detect static routes containing invalid next-hop
        IPv4 or IPv6 addresses.
        """

        findings: List[Finding] = []

        for route in self.firewall.routes:

            if self.route_matcher.is_valid_next_hop(
                route.next_hop
            ):
                continue

            findings.append(
                Finding(
                    severity="MEDIUM",
                    code="FW-025",
                    rule_id=None,
                    line_number=route.line_number,
                    title="Invalid route next-hop address",
                    description=(
                        f"Route {route.destination} uses "
                        f"next-hop address {route.next_hop!r}, "
                        "which is not a valid IPv4 or IPv6 address."
                    ),
                    recommendation=(
                        "Review the static route and configure "
                        "a valid next-hop IP address. Verify "
                        "that the next hop is reachable through "
                        "the intended interface."
                    ),
                    related_rule_id=None,
                )
            )

        return findings

        # ================================================================
    # FW-026: Route next-hop address-family mismatch
    # ================================================================

    def _check_route_next_hop_family_mismatch(self) -> List[Finding]:
        """
        Detect static routes where the destination network
        and next-hop address use different IP versions.
        """

        findings: List[Finding] = []

        for route in self.firewall.routes:

            if not self.route_matcher.has_next_hop_family_mismatch(
                route.destination,
                route.next_hop,
            ):
                continue

            findings.append(
                Finding(
                    severity="MEDIUM",
                    code="FW-026",
                    rule_id=None,
                    line_number=route.line_number,
                    title="Route next-hop address-family mismatch",
                    description=(
                        f"Route destination {route.destination} "
                        f"uses next-hop address {route.next_hop}, "
                        "but their IP address families do not match."
                    ),
                    recommendation=(
                        "Review the static route configuration. "
                        "Ensure the destination network and "
                        "next-hop address use compatible IP "
                        "address families, or verify that the "
                        "platform explicitly supports this "
                        "cross-family routing configuration."
                    ),
                    related_rule_id=None,
                )
            )

        return findings

    # ===============================================================
    # Helper methods
    # ================================================================

    @staticmethod
    def _is_unrestricted_permit(
        rule: FirewallRule,
    ) -> bool:
        """
        Determine whether a rule is genuinely unrestricted.

        Requirements:

            permit action
            any source
            any destination
            ip/any protocol
            no source ports
            no destination ports
        """

        if not rule.is_permit():
            return False

        if not rule.is_any_source():
            return False

        if not rule.is_any_destination():
            return False

        protocol = (
            rule.protocol or ""
        ).strip().lower()

        if protocol not in {
            "ip",
            "any",
        }:
            return False

        if rule.source_ports:
            return False

        if rule.destination_ports:
            return False

        return True

    @staticmethod
    def _same_acl(
        first: FirewallRule,
        second: FirewallRule,
    ) -> bool:
        """
        Determine whether two rules belong to the same ACL.

        Rule.name is used as the ACL identifier.
        """

        first_name = (
            first.name or ""
        ).strip().lower()

        second_name = (
            second.name or ""
        ).strip().lower()

        return first_name == second_name

    def _nat_rule_applies_to_acl(
        self,
        nat_rule: NATRule,
        firewall_rule: FirewallRule,
    ) -> bool:
        """
        Determine whether an ACL rule is a reasonable candidate
        for NAT correlation.

        When interface information is unavailable, address-based
        correlation is still allowed.
        """

        raw_config = (
            nat_rule.raw_config or ""
        ).lower()

        if "nat (" not in raw_config:
            return True

        start = raw_config.find(
            "nat ("
        )

        if start == -1:
            return True

        end = raw_config.find(
            ")",
            start,
        )

        if end == -1:
            return True

        interface_text = raw_config[
            start + 5:end
        ].strip()

        if not interface_text:
            return True

        parts = [
            part.strip()
            for part in interface_text.split(",")
        ]

        if len(parts) != 2:
            return True

        inside_interface = parts[0]
        outside_interface = parts[1]

        acl_interface = (
            firewall_rule.destination_interface
            or ""
        ).strip().lower()

        if not acl_interface:
            return True

        return acl_interface in {
            inside_interface,
            outside_interface,
        }

    def _find_service(
        self,
        name: str,
    ):
        """Find a service object case-insensitively."""

        if not name:
            return None

        service = self.firewall.services.get(
            name
        )

        if service is not None:
            return service

        target = name.strip().lower()

        for service_name, candidate in (
            self.firewall.services.items()
        ):

            if service_name.strip().lower() == target:
                return candidate

        return None


def analyze_firewall(
    firewall: FirewallConfig,
) -> List[Finding]:
    """Convenience function for analyzing a firewall."""

    analyzer = FirewallAnalyzer(
        firewall
    )

    return analyzer.analyze()