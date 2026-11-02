# START HERE: Native Linux support for FirewallAnalyzer

1. Copy the **full analyzer source** into an Ubuntu/Linux VM or Linux computer.
2. Extract this ZIP into the project's root directory.
3. Open `linux_packaging/README_LINUX.md` and follow the Linux commands. Run **all** preflight, regression, packaging and acceptance checks.
4. The Linux output is `linux_release_single/FirewallAnalyzer` (no `.exe`). The Windows EXE is still Windows-only.

**Status:** Builder, launcher and acceptance tools prepared; native Linux launcher was tested against a representative FastAPI app, but the actual full analyzer has not been packaged or tested on a clean Linux machine here. Do not claim Linux release acceptance until those runs pass.
