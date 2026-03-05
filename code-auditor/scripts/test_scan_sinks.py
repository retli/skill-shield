#!/usr/bin/env python3
"""
test_scan_sinks.py — Unit tests for scan_sinks.py

Run: python3 test_scan_sinks.py
"""

import sys
import os
import tempfile
import shutil
import unittest
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent))
from scan_sinks import (
    SinkPattern, Severity, Tier, Finding,
    classify_tier, scan_file, scan_directory, scan_single_file,
    EXT_TO_LANG, LANG_SINKS, UNIVERSAL_SINKS,
)


class TestSinkPatternCompilation(unittest.TestCase):
    """All SinkPattern regex should compile without errors."""

    def test_all_patterns_compile(self):
        for lang, patterns in LANG_SINKS.items():
            for p in patterns:
                self.assertIsNotNone(
                    p.compiled,
                    f"Pattern '{p.name}' in '{lang}' failed to compile: {p.regex}"
                )

    def test_universal_patterns_compile(self):
        for p in UNIVERSAL_SINKS:
            self.assertIsNotNone(
                p.compiled,
                f"Universal pattern '{p.name}' failed to compile: {p.regex}"
            )


class TestEALOCTiering(unittest.TestCase):
    """EALOC tier classification should work correctly."""

    def test_java_controller_is_t1(self):
        self.assertEqual(classify_tier(Path("UserController.java"), "java"), Tier.T1)

    def test_java_service_is_t2(self):
        self.assertEqual(classify_tier(Path("UserService.java"), "java"), Tier.T2)

    def test_java_entity_is_t3(self):
        self.assertEqual(classify_tier(Path("UserEntity.java"), "java"), Tier.T3)

    def test_python_view_is_t1(self):
        self.assertEqual(classify_tier(Path("views.py"), "python"), Tier.T1)

    def test_python_route_is_t1(self):
        self.assertEqual(classify_tier(Path("api_route.py"), "python"), Tier.T1)

    def test_python_service_is_t2(self):
        self.assertEqual(classify_tier(Path("user_service.py"), "python"), Tier.T2)

    def test_python_config_is_t3(self):
        self.assertEqual(classify_tier(Path("config.py"), "python"), Tier.T3)

    def test_go_handler_is_t1(self):
        self.assertEqual(classify_tier(Path("user_handler.go"), "go"), Tier.T1)

    def test_unknown_defaults_to_t2(self):
        self.assertEqual(classify_tier(Path("something.py"), "python"), Tier.T2)

    def test_js_router_is_t1(self):
        self.assertEqual(classify_tier(Path("api_router.js"), "javascript"), Tier.T1)


class TestPythonSinkDetection(unittest.TestCase):
    """Python sink patterns should detect known vulnerabilities."""

    def _scan_code(self, code: str, filename: str = "test.py") -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(Path(f.name), "python", Tier.T2)
        os.unlink(f.name)
        return findings

    def _sink_types(self, findings):
        return [f.sink_type for f in findings]

    def test_eval(self):
        findings = self._scan_code('result = eval(user_input)\n')
        self.assertIn("eval_exec", self._sink_types(findings))

    def test_exec(self):
        findings = self._scan_code('exec(code_string)\n')
        self.assertIn("eval_exec", self._sink_types(findings))

    def test_os_system(self):
        findings = self._scan_code('os.system("ping " + host)\n')
        self.assertIn("os_system", self._sink_types(findings))

    def test_subprocess_shell_true(self):
        findings = self._scan_code('subprocess.check_output("ls " + d, shell=True)\n')
        self.assertIn("subprocess_shell", self._sink_types(findings))

    def test_subprocess_concat(self):
        findings = self._scan_code('subprocess.check_output("ls " + d, shell=True)\n')
        self.assertIn("subprocess_concat", self._sink_types(findings))

    def test_pickle_loads(self):
        findings = self._scan_code('obj = pickle.loads(data)\n')
        self.assertIn("pickle_load", self._sink_types(findings))

    def test_yaml_unsafe(self):
        findings = self._scan_code('config = yaml.load(data)\n')
        self.assertIn("yaml_unsafe", self._sink_types(findings))

    def test_yaml_safe_no_alert(self):
        findings = self._scan_code('config = yaml.load(data, Loader=SafeLoader)\n')
        self.assertNotIn("yaml_unsafe", self._sink_types(findings))

    def test_sql_concat(self):
        findings = self._scan_code('cursor.execute("SELECT * FROM users WHERE id=" + uid)\n')
        self.assertIn("sql_concat", self._sink_types(findings))

    def test_ssti(self):
        findings = self._scan_code('return render_template_string(template)\n')
        self.assertIn("ssti", self._sink_types(findings))

    def test_ssrf_requests(self):
        findings = self._scan_code('resp = requests.get(url)\n')
        self.assertIn("ssrf_requests", self._sink_types(findings))

    def test_path_traversal(self):
        findings = self._scan_code('return send_file("/uploads/" + filename)\n')
        self.assertIn("path_traversal", self._sink_types(findings))

    def test_debug_mode(self):
        findings = self._scan_code('app.run(debug=True)\n')
        self.assertIn("debug_mode", self._sink_types(findings))

    def test_safe_code_no_alerts(self):
        safe_code = """
import json
import os
from pathlib import Path

def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return json.load(f)

def list_files(directory: str) -> list:
    return list(Path(directory).rglob('*.py'))

def process(data: dict) -> str:
    return json.dumps(data, indent=2)
"""
        findings = self._scan_code(safe_code)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(critical), 0, f"Safe code triggered: {[f.sink_type for f in critical]}")


class TestJavaSinkDetection(unittest.TestCase):
    """Java sink patterns should detect known vulnerabilities."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(Path(f.name), "java", Tier.T1)
        os.unlink(f.name)
        return findings

    def _sink_types(self, findings):
        return [f.sink_type for f in findings]

    def test_sql_concat(self):
        findings = self._scan_code('stmt.executeQuery("SELECT * FROM u WHERE id=" + id);\n')
        self.assertIn("sql_concat", self._sink_types(findings))

    def test_runtime_exec(self):
        findings = self._scan_code('Runtime.getRuntime().exec(cmd);\n')
        self.assertIn("runtime_exec", self._sink_types(findings))

    def test_deserialization(self):
        findings = self._scan_code('Object o = new ObjectInputStream(is).readObject();\n')
        self.assertIn("deserialization", self._sink_types(findings))

    def test_mybatis_dollar(self):
        findings = self._scan_code('SELECT * FROM users WHERE name = ${name}\n')
        self.assertIn("mybatis_dollar", self._sink_types(findings))


class TestJavaScriptSinkDetection(unittest.TestCase):
    """JavaScript sink patterns should detect known vulnerabilities."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(Path(f.name), "javascript", Tier.T2)
        os.unlink(f.name)
        return findings

    def _sink_types(self, findings):
        return [f.sink_type for f in findings]

    def test_eval(self):
        findings = self._scan_code('const result = eval(userInput);\n')
        self.assertIn("eval", self._sink_types(findings))

    def test_innerhtml(self):
        findings = self._scan_code('el.innerHTML = response;\n')
        self.assertIn("xss_innerhtml", self._sink_types(findings))

    def test_child_process(self):
        findings = self._scan_code('child_process.exec(cmd);\n')
        self.assertIn("child_process", self._sink_types(findings))


class TestGoSinkDetection(unittest.TestCase):
    """Go sink patterns should detect known vulnerabilities."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".go", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(Path(f.name), "go", Tier.T2)
        os.unlink(f.name)
        return findings

    def _sink_types(self, findings):
        return [f.sink_type for f in findings]

    def test_exec_command(self):
        findings = self._scan_code('cmd := exec.Command("ls")\n')
        self.assertIn("os_exec", self._sink_types(findings))

    def test_template_html(self):
        findings = self._scan_code('out := template.HTML(userInput)\n')
        self.assertIn("template_html", self._sink_types(findings))


class TestScanModes(unittest.TestCase):
    """Test single file and directory scan modes."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        vuln_code = 'result = eval(user_input)\n'
        safe_code = 'print("hello")\n'
        with open(os.path.join(self.tmpdir, "vuln.py"), "w") as f:
            f.write(vuln_code)
        with open(os.path.join(self.tmpdir, "safe.py"), "w") as f:
            f.write(safe_code)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_single_file_scan(self):
        findings, stats = scan_single_file(Path(self.tmpdir) / "vuln.py")
        self.assertEqual(stats["files_scanned"], 1)
        self.assertGreater(len(findings), 0)

    def test_directory_scan(self):
        findings, stats = scan_directory(Path(self.tmpdir))
        self.assertEqual(stats["files_scanned"], 2)
        self.assertGreater(len(findings), 0)

    def test_safe_file_no_critical(self):
        findings, stats = scan_single_file(Path(self.tmpdir) / "safe.py")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(critical), 0)


class TestEALOCCalculation(unittest.TestCase):
    """EALOC should use LOC-based weighting."""

    def test_ealoc_uses_loc(self):
        """Create files of known sizes and verify EALOC calculation."""
        tmpdir = tempfile.mkdtemp()
        try:
            # Controller file (Tier1) with 100 lines
            controller = os.path.join(tmpdir, "UserController.java")
            with open(controller, "w") as f:
                f.write("\n".join([f"// line {i}" for i in range(100)]))

            # Service file (Tier2) with 200 lines
            service = os.path.join(tmpdir, "UserService.java")
            with open(service, "w") as f:
                f.write("\n".join([f"// line {i}" for i in range(200)]))

            # Entity file (Tier3) with 50 lines
            entity = os.path.join(tmpdir, "UserEntity.java")
            with open(entity, "w") as f:
                f.write("\n".join([f"// line {i}" for i in range(50)]))

            _, stats = scan_directory(Path(tmpdir))

            t1_loc = stats["tiers"][Tier.T1]["loc"]
            t2_loc = stats["tiers"][Tier.T2]["loc"]
            t3_loc = stats["tiers"][Tier.T3]["loc"]

            expected_ealoc = t1_loc * 1.0 + t2_loc * 0.5 + t3_loc * 0.1
            self.assertGreater(expected_ealoc, 0)
            # T1 should have ~100 LOC, T2 ~200, T3 ~50
            self.assertGreater(t1_loc, 90)
            self.assertGreater(t2_loc, 190)
            self.assertGreater(t3_loc, 40)
        finally:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
