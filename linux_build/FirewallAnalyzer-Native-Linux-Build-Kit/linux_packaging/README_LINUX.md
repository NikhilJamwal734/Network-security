# FirewallAnalyzer — native Linux desktop build and acceptance

This **additive Linux build kit** uses the **same checked-out application** as your working Windows EXE. It does not modify existing detection rules, `app/api/main.py`, React source or Windows packaging. It requires the full current project checkout; the ZIP itself is **not** the complete analyzer.

## What this does (and does not) guarantee

- Builds a **native Linux executable** named `FirewallAnalyzer`. The Windows `.exe` is **not** usable as a native Linux binary.
- Includes compiled React frontend, FastAPI backend, F5 BIG-IP checks and other Python analysis modules using PyInstaller.
- Keeps the local API bound to **127.0.0.1 only** with a dynamic port. Do **not** expose this desktop API to a public network.
- The launcher maps the existing packaged log path to `$XDG_STATE_HOME/FirewallAnalyzer/logs` (or `~/.local/state/FirewallAnalyzer/logs`), using `LOCALAPPDATA` internally for compatibility with the existing logger. This is not an invitation to change your Windows logger.
- Creates a SHA-256 build receipt, and offers automated Linux acceptance for five vendors, F5 optional evidence, dashboard, logs, Host/Origin checks and graceful shutdown.
- **Not a tested Linux binary yet**: you must build and run it on a Linux machine containing the current analyzer source and verify it on a *second clean Linux installation* before sharing.
- Linux binary compatibility is specific to CPU architecture and glibc/library versions. **Build on the oldest supported target distribution**, e.g. Ubuntu 22.04 x86_64 if that is your intended minimum (assuming your dependencies support it). Build separately for ARM64/aarch64, and test there. PyInstaller does not cross-compile Windows binaries to Linux.

## 1. Transfer your source to an Ubuntu/Linux VM

Use Git or an approved file transfer to put the **full source checkout** in Linux (including `app/`, `frontend/`, `desktop_packaging/`, `release_final/`, the F5 modules/patch fixtures, and the `linux_packaging/` folder extracted from this ZIP). Do **not** copy `.venv-win`, `node_modules`, Windows `.exe`, logs, private device configs, certificates or signing keys. Transfer sanitized test fixtures only.

```bash
cd "$HOME/network-security-configuration-analyzer"   # replace with your actual folder
unzip -o "$HOME/Downloads/FirewallAnalyzer-Linux-Build-Kit.zip" -d .
```

If you used Git to transfer the project, extract the Linux kit after cloning.

## 2. Install Linux prerequisites

For Ubuntu/Debian (not for Windows PowerShell):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential binutils patchelf unzip
python3 --version
node --version
npm --version
```

Install a current Node.js release that satisfies your project's Vite engine requirements (Node.js 22 or later may be appropriate depending on the Vite version). Node and npm are needed on the **builder**, not on the receiving machine.

Set up a Linux Python virtual environment:

```bash
python3 -m venv .venv-linux
.venv-linux/bin/python -m pip install --upgrade pip
```

Install **the project's Linux-compatible backend dependencies** from its maintained requirements/lock file; for example:

```bash
.venv-linux/bin/python -m pip install -r requirements.txt
.venv-linux/bin/python -m pip install 'pyinstaller>=6,<7'
.venv-linux/bin/python -m pip check
```

**If you have no `requirements.txt`, stop and produce a reviewed, Linux-compatible dependency specification first.** Do not blindly reuse a Windows-only `pip freeze` (which may contain Windows-specific wheels).

Install frontend dependencies:

```bash
cd frontend
npm ci
cd ..
```

## 3. Linux preflight, tests and packaging

```bash
.venv-linux/bin/python -m unittest discover -s linux_packaging/tests -p 'test_*.py' -v
.venv-linux/bin/python linux_packaging/build_linux.py --check
.venv-linux/bin/python linux_packaging/build_linux.py
```

The `--check` verifies the source layout, tools and **imports `app.api.main` on Linux** to catch missing or platform-specific dependencies before packaging. It is not a substitute for application regression testing.

Default output:

```text
linux_release_single/FirewallAnalyzer
linux_release_build_receipt.json
```

Alternative, easier-to-debug folder packaging:

```bash
.venv-linux/bin/python linux_packaging/build_linux.py --onedir
# Output: linux_release_folder/FirewallAnalyzer/FirewallAnalyzer
# Distribute the entire linux_release_folder/FirewallAnalyzer directory
```

To repackage an already built React frontend, use `--skip-frontend-build` (advanced only); the builder checks that the expected compiled pages exist.

## Optional: run from source before bundling

Once the backend dependencies and React production assets are in place, you can test the Linux launcher without PyInstaller:

```bash
.venv-linux/bin/python linux_packaging/build_linux.py --check
cd frontend && npm run build && cd ..
.venv-linux/bin/python linux_packaging/launcher.py --no-browser
```

The source launcher uses the same local FastAPI/React port strategy; the production binary is still built separately. If the Logs page is enabled, use the full multipage builder instead of relying on a standalone `npm run build` for the final release.

## 4. Acceptance test the exact Linux binary

The acceptance script only launches the binary **after verifying SHA-256** against `linux_release_build_receipt.json`. It uses the sanitized fixtures from your project. It does not save sensitive configuration data or log contents in the acceptance result.

```bash
.venv-linux/bin/python linux_packaging/accept_linux.py --root .
```

Expected status: `AUTOMATED PACKAGED ACCEPTANCE: PASS` (after actual execution). Inspect `linux_release_acceptance_result.json` for details. If the shutdown check returns `INCOMPLETE`, manually verify Ctrl+C, zero exit status and that the local API port stopped, as you did on Windows.

If you built with `--onedir`, specify the actual executable:

```bash
.venv-linux/bin/python linux_packaging/accept_linux.py --root . \
  --exe linux_release_folder/FirewallAnalyzer/FirewallAnalyzer
```

**Also manually test:** React navigation, PDF generation, the JSON Logs viewer's colors, the F5 3/5 and 4/4 sample scenarios, error handling, and all four other vendor reports. Run your active regression suite on Linux, review every failure/skip and inspect the PDF. The automated smoke tests are not a production security certification.

## 5. Share it with another Linux computer

Once the build and acceptance have passed, create an archive on the **Linux** machine:

```bash
sha256sum linux_release_single/FirewallAnalyzer
mkdir -p linux_distribution
cp linux_release_single/FirewallAnalyzer linux_distribution/
cp linux_release_build_receipt.json linux_distribution/
tar -czf FirewallAnalyzer-linux-$(uname -m).tar.gz -C linux_distribution .
```

On the receiving compatible Linux machine:

```bash
tar -xzf FirewallAnalyzer-linux-x86_64.tar.gz
sha256sum FirewallAnalyzer    # compare with trusted receipt
chmod +x FirewallAnalyzer
./FirewallAnalyzer --no-browser
```

The URL printed by the binary is **local to that Linux machine**. Open it using a browser on the same system. The frontend and API do not need a separate Node or Python installation on the recipient, provided the PyInstaller bundle and native libraries are compatible. Some minimal/headless distros need additional native system libraries. Avoid publishing the unsanitized source, configuration files, device credentials, signing keys or audit logs.

## Troubleshooting

- `No module named ...` during preflight: install/fix the relevant Linux backend dependency, then rerun tests.
- `GLIBC_2.xx not found`: rebuild on an *older* supported Linux distribution/compatible glibc, for the correct architecture.
- `npm run build` fails: check Node/Vite compatibility and frontend TypeScript errors.
- Missing `logs.html`: the Linux builder requires the complete multipage Logs frontend when the Logs feature is installed.
- `Permission denied`: `chmod +x` and verify the target filesystem is not mounted `noexec`. Onefile builds also use a temp extraction location; a `noexec` temp partition may prevent them from launching. Use `--onedir` if necessary.
- `Connection refused` from a different computer: expected; this **desktop** build listens on loopback only. Deploying it as a multi-user Linux server needs a separate HTTPS/authenticated server mode.
- Linux logs are at `~/.local/state/FirewallAnalyzer/logs` unless `XDG_STATE_HOME` is set.
- Test on a clean Ubuntu VM without Python/Node first, then on each additional Linux version/architecture you want to support.

## Source modifications and security

The ZIP contains only `linux_packaging/` source, tests and documentation. It does not overwrite application/backend/frontend files. You must still manually review dependencies and verify the real Linux build; this kit cannot claim that the existing Windows-tested application is fully Linux-compatible without those tests.
