import unittest

from cortex_shield.sandbox import DockerShellSandbox, SandboxUnavailableError


class FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class DockerShellSandboxTests(unittest.TestCase):
    def test_runs_shell_command_inside_locked_down_docker_container(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            return FakeCompletedProcess(returncode=0, stdout="ok\n", stderr="")

        sandbox = DockerShellSandbox(image="alpine:3.20", timeout_seconds=7, run_command=fake_run)

        result = sandbox.run("echo ok")

        args, kwargs = calls[0]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stdout"], "ok\n")
        self.assertIn("--network", args)
        self.assertIn("none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--pids-limit", args)
        self.assertIn("--memory", args)
        self.assertIn("--tmpfs", args)
        self.assertEqual(args[-3:], ["sh", "-lc", "echo ok"])
        self.assertFalse(any(part.startswith("/Users/") for part in args))
        self.assertEqual(kwargs["timeout"], 7)
        self.assertFalse(kwargs["shell"])

    def test_fails_closed_when_docker_is_missing(self):
        def fake_run(args, **kwargs):
            raise FileNotFoundError("docker")

        sandbox = DockerShellSandbox(run_command=fake_run)

        with self.assertRaises(SandboxUnavailableError):
            sandbox.run("pwd")


if __name__ == "__main__":
    unittest.main()
