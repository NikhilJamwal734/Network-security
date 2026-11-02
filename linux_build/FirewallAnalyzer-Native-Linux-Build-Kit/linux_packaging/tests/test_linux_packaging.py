from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.request import urlopen, Request, build_opener, ProxyHandler
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]

def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

build = load('build_linux.py','build_linux_test')
accept = load('accept_linux.py','accept_linux_test')


def fake_tree(root):
    for rel in ('app/api/main.py', 'frontend/package.json', 'frontend/index.html', 'linux_packaging/launcher.py',
                'frontend/dist/index.html'):
        file=root / rel
        file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text('<html>test</html>' if file.suffix == '.html' else 'pass', encoding='utf8')
    return root


class PlanningTests(unittest.TestCase):
    def test_project_layout(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_tree(Path(t))
            self.assertFalse(build.check_layout(root)['logs_html'])

    def test_no_logs_multipage_noop(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_tree(Path(t)); frontend=root/'frontend'
            with build.temporary_multipage_config(frontend):
                self.assertFalse((frontend/'.firewall-linux-vite.config.mts').exists())

    def test_logging_requires_both_frontend_components(self):
        with tempfile.TemporaryDirectory() as t:
            root=fake_tree(Path(t)); (root/'frontend/logs.html').write_text('hi')
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                build.check_layout(root)

    def test_packaging_command_linux_data_separator(self):
        with tempfile.TemporaryDirectory() as t:
            root=fake_tree(Path(t)); cmd=build.build_command(root,'python3')
            self.assertIn('--onefile',cmd)
            self.assertIn('--collect-submodules',cmd)
            self.assertIn(f"{root/'frontend/dist'}{os.pathsep}frontend/dist",cmd)
            self.assertTrue(cmd[-1].endswith('/linux_packaging/launcher.py'))

    def test_packaging_command_onedir(self):
        with tempfile.TemporaryDirectory() as t:
            root=fake_tree(Path(t)); cmd=build.build_command(root,'python3',onefile=False)
            self.assertIn('--onedir',cmd)
            self.assertNotIn('--onefile',cmd)

    def test_temporary_multipage_restored(self):
        with tempfile.TemporaryDirectory() as t:
            root=fake_tree(Path(t));frontend=root/'frontend'
            (frontend/'logs.html').write_text('logs');(frontend/'vite.config.ts').write_text('export default {}')
            target=frontend/'.firewall-linux-vite.config.mts'
            with build.temporary_multipage_config(frontend):
                self.assertTrue(target.exists())
                self.assertIn('logs.html',target.read_text())
            self.assertFalse(target.exists())

    def test_preexisting_temp_config_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root=fake_tree(Path(t));frontend=root/'frontend'
            (frontend/'logs.html').write_text('logs');(frontend/'vite.config.ts').write_text('export default {}')
            (frontend/'.firewall-linux-vite.config.mts').write_text('existing')
            with self.assertRaises(FileExistsError):
                with build.temporary_multipage_config(frontend): pass

    def test_receipt_has_hash_and_does_not_claim_pass(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); exe=root/'FirewallAnalyzer';exe.write_bytes(b'a'*102400)
            receipt=build.write_receipt(root,exe,onefile=True)
            data=json.loads(receipt.read_text())
            self.assertEqual(data['status'],'BUILT_NOT_ACCEPTED')
            self.assertEqual(data['binary_sha256'],hashlib.sha256(exe.read_bytes()).hexdigest())
            self.assertEqual(accept.integrity_check(exe,receipt)['status'],'PASS')
            exe.write_bytes(b'b'*102400)
            self.assertEqual(accept.integrity_check(exe,receipt)['status'],'FAIL')

    def test_symlink_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);exe=root/'FirewallAnalyzer';exe.write_bytes(b'a'*102400)
            target=root/'real.json';target.write_text('stub')
            try: (root/'linux_release_build_receipt.json').symlink_to(target)
            except (OSError,NotImplementedError): self.skipTest('no symlink permission')
            with self.assertRaises(ValueError): build.write_receipt(root,exe,onefile=True)

    def test_linux_termination_no_process_leak(self):
        proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(25)'],start_new_session=True)
        try:
            accept.stop_child(proc)
            self.assertIsNotNone(proc.poll())
        finally:
            if proc.poll() is None:
                proc.kill();proc.wait()


class RealLocalLauncherSmoke(unittest.TestCase):
    def test_unfrozen_launcher_loopback_and_shutdown(self):
        # Exercised against real FastAPI/Uvicorn on this Linux container, with a tiny fake project.
        if not sys.platform.startswith('linux'):
            self.skipTest('Linux-only test')
        if importlib.util.find_spec('fastapi') is None or importlib.util.find_spec('uvicorn') is None:
            self.skipTest('FastAPI/Uvicorn not installed')
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); fake_tree(root)
            shutil.copy2(ROOT/'launcher.py',root/'linux_packaging/launcher.py')
            (root/'app/__init__.py').write_text('')
            (root/'app/api/__init__.py').write_text('')
            (root/'app/api/main.py').write_text('''from fastapi import FastAPI\nimport os\napp=FastAPI()\n@app.get('/api/health')\ndef health(): return {'status':'ok','state_dir':os.environ.get('LOCALAPPDATA')}\n''')
            (root/'frontend/dist/index.html').write_text('<html><body>test index</body></html>')
            (root/'frontend/dist/index.js').write_text('const API="http://127.0.0.1:8000";')
            env=os.environ.copy(); env['XDG_STATE_HOME']=str(root/'xdg_state')
            proc=subprocess.Popen([sys.executable,'-u',str(root/'linux_packaging/launcher.py'),'--no-browser'],
                 cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',text=True,
                 start_new_session=True,bufsize=1)
            output=queue.Queue()
            threading.Thread(target=accept.collect_output,args=(proc.stdout,output),daemon=True).start()
            try:
                base=accept.announce(proc,output,12)
                self.assertTrue(base,'no URL announced')
                self.assertTrue(accept.await_readiness(base,8))
                opener=build_opener(ProxyHandler({}))
                with opener.open(base+'api/health',timeout=3) as r:
                    data=json.load(r)
                self.assertEqual(data['status'],'ok')
                self.assertEqual(data['state_dir'],str(root/'xdg_state'))
                with opener.open(base+'index.js',timeout=3) as r:
                    content=r.read().decode()
                self.assertIn(base.rstrip('/'),content)
                self.assertNotIn('http://127.0.0.1:8000',content)
                with self.assertRaises(HTTPError) as e:
                    opener.open(Request(base,headers={'Host':'attacker.invalid'}),timeout=3)
                self.assertEqual(e.exception.code,400)
                stopped=accept.request_graceful_shutdown(proc,base)
                self.assertEqual(stopped['status'],'PASS',stopped)
            finally:
                accept.stop_child(proc)
                if proc.stdout: proc.stdout.close()


if __name__ == '__main__': unittest.main()
