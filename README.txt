F5 Phase 1 UI Windows Encoding Test Fix

This patch changes only f5_phase1_ui_patch/tests/test_f5_ui.py.
It adds explicit UTF-8 encoding when reading the TypeScript fixtures and when rewriting the fixture in the partial-integration test.

Install: Extract ZIP into your existing project root and allow overwrite of the test file.
Run: .\.venv-win\Scripts\python.exe -m pytest -q .\f5_phase1_ui_patch\tests

No application or installer code is changed.
