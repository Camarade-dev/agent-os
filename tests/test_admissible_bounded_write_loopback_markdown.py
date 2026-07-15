"""Regression tests for the Markdown loopback-documentation content-guard repair.

These tests pin the exact false positive recovered from the first real Slice 4
live run (session ``neon-serpents-live-001``): a bare loopback URL appearing as
inert Markdown documentation was rejected as ``forbidden network call in write
content``.  The repair exempts *only* strict loopback HTTP(S) URLs in Markdown
while preserving every other network protection.
"""

from __future__ import annotations

import unittest

from admissible.execution.bounded_write import (
    BoundedWriteError,
    forbidden_write_content_reason,
    validate_bounded_write_content,
)

# The exact inert documentation line recovered from the rejected op-4 content.
RECOVERED_MARKDOWN_LINE = (
    "Then open `http://localhost:8080/index.html` "
    "(adjust the port to match your server)."
)

# A representative LOCAL_DEV.md faithful to the recovered file's shape without
# hard-coding its exact bytes: file:// opening, a python static server, an npx
# server, and the loopback browser URL.
REPRESENTATIVE_LOCAL_DEV = (
    "# Local Development\n\n"
    "Open `index.html` directly, or from `file://` in a permissive browser.\n\n"
    "### Optional static server\n\n"
    "```bash\n"
    "python -m http.server 8080\n"
    "npx serve .\n"
    "```\n\n"
    "Then open `http://localhost:8080/index.html` (adjust the port).\n"
)


class RecoveredFailurePassesTest(unittest.TestCase):
    def test_exact_recovered_line_passes(self) -> None:
        self.assertIsNone(forbidden_write_content_reason("LOCAL_DEV.md", RECOVERED_MARKDOWN_LINE))

    def test_representative_local_dev_passes(self) -> None:
        self.assertIsNone(forbidden_write_content_reason("LOCAL_DEV.md", REPRESENTATIVE_LOCAL_DEV))

    def test_validate_bounded_write_content_accepts_recovered_line(self) -> None:
        # This is the exact per-operation content check the V0 admission adapter
        # invokes (admissible/v0_controller/adapters.py -> validate_bounded_write_content).
        validate_bounded_write_content("LOCAL_DEV.md", RECOVERED_MARKDOWN_LINE)


class StrictLoopbackAllowedInMarkdownTest(unittest.TestCase):
    LOOPBACK_URLS = (
        "http://localhost:8080/index.html",
        "https://localhost/",
        "http://127.0.0.1:3000/",
        "http://[::1]:8080/index.html",
        "http://localhost/",
        "https://127.0.0.1/path?query=1#frag",
    )

    def test_bare_loopback_urls_allowed(self) -> None:
        for url in self.LOOPBACK_URLS:
            with self.subTest(url=url):
                content = f"Then open `{url}` in your browser."
                self.assertIsNone(forbidden_write_content_reason("DOC.md", content))


class ExternalAndDeceptiveUrlsRejectedTest(unittest.TestCase):
    REJECTED_URLS = (
        "https://cdn.example.com/library.js",
        "http://example.com/",
        "http://localhost.example.com/",
        "http://127.0.0.1.example.com/",
        "http://user@localhost:8080/",
        "http://localhost@evil.example/",
    )

    def test_external_and_deceptive_urls_rejected(self) -> None:
        for url in self.REJECTED_URLS:
            with self.subTest(url=url):
                content = f"Then open `{url}` in your browser."
                self.assertEqual(
                    forbidden_write_content_reason("DOC.md", content),
                    "forbidden network call in write content",
                )

    def test_external_url_still_fails_validate(self) -> None:
        with self.assertRaises(BoundedWriteError):
            validate_bounded_write_content(
                "LOCAL_DEV.md",
                RECOVERED_MARKDOWN_LINE.replace("localhost", "cdn.example.com"),
            )


class ExecutableNetworkConstructsRejectedInMarkdownTest(unittest.TestCase):
    # Executable/shell network constructs must remain forbidden even when they
    # target a strict loopback host.
    EXECUTABLE_SNIPPETS = (
        'fetch("http://localhost:8080/data")',
        "const x = new XMLHttpRequest();",
        'new WebSocket("ws://localhost:8080")',
        'new EventSource("http://localhost:8080/events")',
        'navigator.sendBeacon("http://localhost/collect", data)',
        "curl http://localhost:8080/",
        "wget http://localhost:8080/",
    )

    def test_executable_network_constructs_rejected(self) -> None:
        for snippet in self.EXECUTABLE_SNIPPETS:
            with self.subTest(snippet=snippet):
                content = f"Example usage:\n\n```js\n{snippet}\n```\n"
                self.assertEqual(
                    forbidden_write_content_reason("DOC.md", content),
                    "forbidden network call in write content",
                )


class NonMarkdownBehaviorUnchangedTest(unittest.TestCase):
    def test_js_external_url_still_rejected(self) -> None:
        self.assertEqual(
            forbidden_write_content_reason("a.js", 'fetch("https://x.example.com")'),
            "forbidden network call in write content",
        )

    def test_js_loopback_url_still_rejected(self) -> None:
        # The loopback exemption is Markdown-only; JS is unchanged.
        self.assertEqual(
            forbidden_write_content_reason("a.js", 'const u = "http://localhost:8080";'),
            "forbidden network call in write content",
        )

    def test_css_external_reference_still_rejected(self) -> None:
        self.assertEqual(
            forbidden_write_content_reason("a.css", "background:url(https://cdn.example.com/x.png)"),
            "forbidden network reference in write content",
        )

    def test_html_external_resource_still_rejected(self) -> None:
        self.assertEqual(
            forbidden_write_content_reason(
                "a.html", '<script src="https://cdn.example.com/x.js"></script>'
            ),
            "forbidden external resource reference in write content",
        )

    def test_plain_json_and_text_unaffected(self) -> None:
        self.assertIsNone(forbidden_write_content_reason("a.json", '{"note": "hello"}'))
        self.assertIsNone(forbidden_write_content_reason("README.md", "Local-only docs, no URLs."))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
