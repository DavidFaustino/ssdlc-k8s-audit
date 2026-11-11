import unittest

from auditlib.documents import render_markdown


class DocumentTests(unittest.TestCase):
    def test_tables_headings_and_code_are_readable_without_running_html(self):
        text = '# Guia\n\n| Item | Valor |\n|---|---|\n| CT-01 | <script>bad()</script> |\n\n```bash\naws --version\n```\n'
        out = render_markdown(text, "Guia")
        self.assertIn("<table>", out)
        self.assertIn("<td>CT-01</td>", out)
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt;", out)
        self.assertNotIn("<script>", out)
        self.assertIn("<pre><code", out)

    def test_links_reject_script_protocol_and_map_known_docs(self):
        out = render_markdown('[ruim](javascript:alert) [Guia](RUNBOOK.md) [AWS](https://docs.aws.amazon.com/)', "Teste")
        self.assertNotIn('href="javascript:', out)
        self.assertIn('href="RUNBOOK.html"', out)
        self.assertIn('href="https://docs.aws.amazon.com/"', out)


if __name__ == "__main__":
    unittest.main()
