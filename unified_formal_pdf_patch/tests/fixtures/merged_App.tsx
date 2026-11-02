import {
  lazy,
  Suspense,
  useEffect,
  useRef,
  useState,
} from "react";

/* API-008.4: Load each page only when requested. */

const UniversalAnalysis = lazy(() => import("./pages/UniversalAnalysis"));
const NormalizedReportsPage = lazy(() => import("./pages/NormalizedReportsPage"));
const Findings = lazy(() => import("./pages/Findings"));
const FirewallRules = lazy(() => import("./pages/FirewallRules"));
const NetworkObjects = lazy(() => import("./pages/NetworkObjects"));
const ServiceObjects = lazy(() => import("./pages/ServiceObjects"));
const NATRules = lazy(() => import("./pages/NATRules"));
const Routes = lazy(() => import("./pages/Routes"));
const Configuration = lazy(() => import("./pages/Configuration"));
const Reports = lazy(() => import("./pages/Reports"));

/* EXISTING REPORT EXPORTS */

import JsonReportDownload from "./components/JsonReportDownload";
import PdfReportDownload from "./components/PdfReportDownload";
import NormalizedReportDownloads from "./components/NormalizedReportDownloads";

/* API-008.3 COMPONENTS */

import AnalysisFeedback from "./components/AnalysisFeedback";
import type { NormalizedReport } from "./api/universal";

/* STYLES */

import "./index.css";
import "./AppResponsive.css";

/* ============================================================
   NAVIGATION TYPES
   ============================================================ */

type PageName =
  | "Dashboard"
  | "Findings"
  | "Rules"
  | "Network Objects"
  | "Service Objects"
  | "NAT Rules"
  | "Routes"
  | "Configuration"
  | "Reports";

type NavItem = {
  label: PageName;
  icon: string;
};

/* ============================================================
   SIDEBAR NAVIGATION
   ============================================================ */

const navItems: NavItem[] = [
  { label: "Dashboard", icon: "▦" },
  { label: "Findings", icon: "⚠" },
  { label: "Rules", icon: "≡" },
  { label: "Network Objects", icon: "◈" },
  { label: "Service Objects", icon: "◇" },
  { label: "NAT Rules", icon: "↔" },
  { label: "Routes", icon: "⇄" },
  { label: "Configuration", icon: "⚙" },
  { label: "Reports", icon: "▤" },
];

/* ============================================================
   APPLICATION
   ============================================================ */

function App() {
  const [activePage, setActivePage] =
    useState<PageName>("Dashboard");

  // State lives in App so normalized findings persist when switching to ASA details.
  const [unifiedReport, setUnifiedReport] = useState<NormalizedReport | null>(null);
  const [legacyASAReady, setLegacyASAReady] = useState(false);

  const [mobileMenuOpen, setMobileMenuOpen] =
    useState(false);

  const menuButtonRef =
    useRef<HTMLButtonElement>(null);

  const firstNavButtonRef =
    useRef<HTMLButtonElement>(null);

  const pageContentRef =
    useRef<HTMLDivElement>(null);

  /* ----------------------------------------------------------
     MOBILE MENU KEYBOARD SUPPORT
     ---------------------------------------------------------- */

  useEffect(() => {
    if (!mobileMenuOpen) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setMobileMenuOpen(false);
        menuButtonRef.current?.focus();
      }
    }

    window.addEventListener(
      "keydown",
      handleKeyDown
    );

    // Move keyboard focus into the opened navigation.
    firstNavButtonRef.current?.focus();

    return () => {
      window.removeEventListener(
        "keydown",
        handleKeyDown
      );
    };
  }, [mobileMenuOpen]);

  /* ----------------------------------------------------------
     CLOSE THE MOBILE MENU WHEN DESKTOP SIZE IS RESTORED
     ---------------------------------------------------------- */

  useEffect(() => {
    const mediaQuery = window.matchMedia(
      "(min-width: 901px)"
    );

    function handleDesktopChange() {
      if (mediaQuery.matches) {
        setMobileMenuOpen(false);
      }
    }

    mediaQuery.addEventListener(
      "change",
      handleDesktopChange
    );

    return () => {
      mediaQuery.removeEventListener(
        "change",
        handleDesktopChange
      );
    };
  }, []);

  /* ----------------------------------------------------------
     NAVIGATION HANDLERS
     ---------------------------------------------------------- */

  function navigateTo(page: PageName) {
    setActivePage(page);
    setMobileMenuOpen(false);

    // Focus the selected page's content after navigation.
    window.requestAnimationFrame(() => {
      pageContentRef.current?.focus();
    });
  }

  function closeMobileMenu() {
    setMobileMenuOpen(false);

    window.requestAnimationFrame(() => {
      menuButtonRef.current?.focus();
    });
  }

  /* ==========================================================
     RENDER
     ========================================================== */

  return (
    <div className="app fa-responsive-app">
      {/* ACCESSIBILITY: SKIP NAVIGATION */}

      <a
        href="#fa-main-content"
        className="fa-skip-link"
      >
        Skip to main content
      </a>

      {/* MOBILE NAVIGATION BACKDROP */}

      {mobileMenuOpen && (
        <button
          type="button"
          className="fa-mobile-overlay"
          onClick={closeMobileMenu}
          aria-label="Close navigation menu"
          tabIndex={-1}
        />
      )}

      {/* =====================================================
          SIDEBAR
          ===================================================== */}

      <aside
        id="fa-main-navigation"
        className={`sidebar ${
          mobileMenuOpen
            ? "fa-sidebar-open"
            : ""
        }`}
      >
        {/* BRAND */}

        <div className="brand">
          <div className="brand-mark">
            <span>⛨</span>
          </div>

          <div>
            <div className="brand-title">
              Network Security
            </div>

            <div className="brand-subtitle">
              Configuration Analyzer
            </div>
          </div>
        </div>

        {/* NAVIGATION */}

        <nav
          className="navigation"
          aria-label="Primary navigation"
        >
          <div className="nav-section-title">
            ANALYSIS
          </div>

          {navItems
            .filter((item) => item.label === "Dashboard" ||
              (unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady))
            .map((item, index) => (
            <button
              key={item.label}
              ref={
                index === 0
                  ? firstNavButtonRef
                  : undefined
              }
              type="button"
              className={`nav-item ${
                activePage === item.label
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                navigateTo(item.label)
              }
              aria-current={
                activePage === item.label
                  ? "page"
                  : undefined
              }
            >
              <span
                className="nav-icon"
                aria-hidden="true"
              >
                {item.icon}
              </span>

              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        {/* SIDEBAR FOOTER */}

        <div className="sidebar-footer">
          <div className="system-status">
            <span
              className="status-dot"
              aria-hidden="true"
            />

            <div>
              <div className="status-label">
                Analyzer Online
              </div>

              <div className="status-detail">
                System ready
              </div>
            </div>
          </div>

          <div className="version">
            v1.0.0
          </div>
        </div>
      </aside>

      {/* =====================================================
          MAIN CONTENT
          ===================================================== */}

      <main
        className="main-content"
        id="fa-main-content"
      >
        {/* TOP BAR */}

        <header className="topbar">
          <div className="fa-topbar-start">
            {/* MOBILE MENU BUTTON */}

            <button
              ref={menuButtonRef}
              type="button"
              className="fa-mobile-menu-button"
              aria-label={
                mobileMenuOpen
                  ? "Close navigation"
                  : "Open navigation"
              }
              aria-controls="fa-main-navigation"
              aria-expanded={mobileMenuOpen}
              onClick={() =>
                setMobileMenuOpen((open) => !open)
              }
            >
              <span aria-hidden="true">
                {mobileMenuOpen ? "✕" : "☰"}
              </span>
            </button>

            {/* MOBILE BRAND */}

            <div className="mobile-brand">
              <div className="brand-mark small">
                <span>⛨</span>
              </div>

              <span>
                Security Analyzer
              </span>
            </div>
          </div>

          {/* EXPORT ACTIONS */}

          <div className="topbar-right">
            {unifiedReport?.platform.platform_id === "cisco_asa" && legacyASAReady ? (
              <div className="fa-topbar-downloads">
                <JsonReportDownload />
                <PdfReportDownload />
              </div>
            ) : unifiedReport ? (
              <NormalizedReportDownloads
                report={unifiedReport}
                filename={unifiedReport.platform.hostname || unifiedReport.platform.platform_id}
                compact
              />
            ) : null}

            <span className="environment">
              <span
                className="status-dot"
                aria-hidden="true"
              />

              Local Analysis
            </span>

            <div
              className="user-avatar"
              aria-label="Firewall Analyzer"
            >
              FA
            </div>
          </div>
        </header>

        {/* PAGE CONTENT */}

        <div
          ref={pageContentRef}
          className="page-content"
          tabIndex={-1}
        >
          {/* GLOBAL ANALYSIS STATUS */}

          {unifiedReport?.platform.platform_id === "cisco_asa" && <AnalysisFeedback />}

          <Suspense
            fallback={
              <div
                role="status"
                aria-live="polite"
                style={{ padding: "24px 0" }}
              >
                Loading {activePage}...
              </div>
            }
          >
            {/* DASHBOARD */}

            {activePage === "Dashboard" && (
              <UniversalAnalysis
                report={unifiedReport}
                onReportChange={setUnifiedReport}
                legacyASAReady={legacyASAReady}
                onLegacyASAReadyChange={setLegacyASAReady}
              />
            )}

            {/* FINDINGS */}

            {activePage === "Findings" && (
              <Findings />
            )}

            {/* FIREWALL RULES */}

            {activePage === "Rules" && (
              <FirewallRules />
            )}

            {/* NETWORK OBJECTS */}

            {activePage === "Network Objects" && (
              <NetworkObjects />
            )}

            {/* SERVICE OBJECTS */}

            {activePage === "Service Objects" && (
              <ServiceObjects />
            )}

            {/* NAT RULES */}

            {activePage === "NAT Rules" && (
              <NATRules />
            )}

            {/* ROUTES */}

            {activePage === "Routes" && (
              <Routes />
            )}

            {/* CONFIGURATION */}

            {activePage === "Configuration" && (
              <Configuration />
            )}

            {/* REPORTS */}

            {activePage === "Reports" && unifiedReport && (
              unifiedReport.platform.platform_id === "cisco_asa" && legacyASAReady ? (
                <Reports />
              ) : (
                <NormalizedReportsPage
                  report={unifiedReport}
                  filename={unifiedReport.platform.hostname || unifiedReport.platform.platform_id}
                />
              )
            )}
          </Suspense>
        </div>
      </main>
    </div>
  );
}

export default App;
