"""Synthetic offline tests for publication preflight; no private inputs."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "check_publication_candidate_r1.py"
spec = importlib.util.spec_from_file_location("candidate_check", SOURCE)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PublicationCheckerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, content):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")
        return name

    def test_clean(self):
        name = self.write("docs/synthetic.md", "# Synthetic changes\n")
        self.assertEqual(checker.check_one(self.root, name), [])

    def test_home_path(self):
        name = self.write("a.md", "/" + "home/" + "example-user/" + "private/notes")
        self.assertIn("HOST_HOME_PATH", checker.check_one(self.root, name))

    def test_media_path(self):
        name = self.write("a.md", "/" + "run/media/" + "example-user/" + "drive")
        self.assertIn("HOST_MEDIA_PATH", checker.check_one(self.root, name))

    def test_token(self):
        name = self.write("a.md", "ghp_" + "X" * 35)
        self.assertIn("TOKEN_SIGNATURE", checker.check_one(self.root, name))

    def test_assignment(self):
        name = self.write("a.md", 'password = "synthetic-long-value"')
        self.assertIn("POSSIBLE_CREDENTIAL_ASSIGNMENT", checker.check_one(self.root, name))

    def test_private_key_header(self):
        name = self.write("a.md", "-----BEGIN " + "PRIVATE KEY-----")
        self.assertIn("PRIVATE_KEY_MATERIAL", checker.check_one(self.root, name))

    def test_private_address(self):
        name = self.write("a.md", "address: " + "192." + "168.2.3")
        self.assertIn("PRIVATE_IPV4", checker.check_one(self.root, name))

    def test_absolute(self):
        self.assertIn("UNSAFE_RELATIVE_PATH", checker.check_one(self.root, "/tmp/example.md"))

    def test_parent_directory(self):
        self.assertIn("UNSAFE_RELATIVE_PATH", checker.check_one(self.root, "../outside.md"))

    def test_hidden_private_component(self):
        self.assertIn("PRIVATE_PATH_COMPONENT", checker.check_one(self.root, ".ssh/test.md"))

    def test_private_extension(self):
        self.assertIn("UNSUPPORTED_FILE_TYPE", checker.check_one(self.root, "example.pem"))

    def test_binary(self):
        (self.root / "data.md").write_bytes(b"\x00\x01")
        self.assertIn("BINARY_CONTENT", checker.check_one(self.root, "data.md"))

    def test_symlink(self):
        self.write("source.md", "safe")
        (self.root / "link.md").symlink_to(self.root / "source.md")
        self.assertIn("SYMLINK_NOT_ALLOWED", checker.check_one(self.root, "link.md"))

    def test_not_regular(self):
        (self.root / "folder.md").mkdir()
        self.assertIn("NOT_REGULAR_FILE", checker.check_one(self.root, "folder.md"))

    def test_missing_file(self):
        self.assertIn("UNREADABLE_OR_OUTSIDE_ROOT", checker.check_one(self.root, "absent.md"))

    def test_too_large(self):
        name = self.write("big.md", "x" * (checker.MAX_BYTES + 1))
        self.assertIn("FILE_TOO_LARGE", checker.check_one(self.root, name))

    def test_issue_does_not_contain_matched_input(self):
        name = self.write("a.md", "/" + "home/" + "example-user/" + "very-private")
        self.assertNotIn("example-user", str(checker.check_one(self.root, name)))


if __name__ == "__main__":
    unittest.main()
