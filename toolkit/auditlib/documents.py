"""Renderização de um subconjunto de Markdown local, sempre escapando HTML."""
import html
import re

CSS = """body{margin:0;background:#f3f5f8;color:#172b4d;font:16px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
main{max-width:1120px;margin:32px auto;background:white;padding:40px;border-radius:12px;box-shadow:0 2px 10px #172b4d12}
h1{font-size:30px;line-height:1.2;color:#102a43}h2{font-size:23px;margin-top:38px;border-top:2px solid #dbe5ef;padding-top:20px}h3{font-size:19px;margin-top:26px}
p,li{max-width:100%}a{color:#0052cc}code{font:14px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;background:#edf2f7;padding:2px 4px;border-radius:3px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#102a43;color:#eef5fc;border-radius:7px;padding:18px}pre code{background:none;color:inherit;padding:0}
.table-wrap{overflow-x:auto;margin:18px 0}table{border-collapse:collapse;width:100%;font-size:14px}th{text-align:left;background:#e8f0fb;color:#102a43}th,td{border:1px solid #d9e2ec;padding:10px 12px;vertical-align:top;min-width:100px}tr:nth-child(even){background:#f8fafc}
blockquote{border-left:4px solid #0052cc;padding:10px 18px;background:#eef5ff;margin:20px 0}footer{font-size:12px;color:#526777;margin-top:36px}
@media(max-width:700px){main{margin:0;padding:18px;border-radius:0}h1{font-size:25px}th,td{padding:7px}}
@media print{body{background:white}main{box-shadow:none;margin:0;padding:0;max-width:none}h2,h3{break-after:avoid}tr{break-inside:avoid}a{color:inherit}}
"""


def inline(text):
    text = html.escape(text)
    def link(match):
        label, target = match.groups()
        if target.startswith(("http://", "https://")) or re.fullmatch(r"[A-Za-z0-9_./-]+(?:#[A-Za-z0-9_-]+)?", target):
            if target in {"README.md", "RUNBOOK.md", "PERMISSOES.md", "VALIDACAO.md", "CONFLUENCE-HARDENING.md"}:
                target = target[:-3] + ".html"
            return '<a href="' + target + '">' + label + '</a>'
        return label + " (link omitido)"
    text = re.sub(r"\[([^\]]+)\]\(([^\s)]+)\)", link, text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def render_markdown(text, title):
    lines = text.splitlines()
    parts, paragraph = [], []
    def flush():
        if paragraph:
            parts.append("<p>" + inline(" ".join(paragraph)) + "</p>")
            paragraph.clear()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            i += 1
            code = []
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            parts.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
        elif line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|\-]+\|$", lines[i + 1]):
            flush()
            split = lambda row: [c.replace("\\|", "|").strip() for c in re.split(r"(?<!\\)\|", row.strip().strip("|"))]
            headers = split(line)
            parts.append('<div class="table-wrap"><table><thead><tr>' + "".join("<th>" + inline(c) + "</th>" for c in headers) + "</tr></thead><tbody>")
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                parts.append("<tr>" + "".join("<td>" + inline(c) + "</td>" for c in split(lines[i])) + "</tr>")
                i += 1
            parts.append("</tbody></table></div>")
            continue
        elif line.startswith("#"):
            flush()
            match = re.match(r"^(#{1,6})\s+(.*)$", line)
            if match:
                level = str(len(match[1]))
                parts.append("<h" + level + ">" + inline(match[2]) + "</h" + level + ">")
            else:
                paragraph.append(line)
        elif re.match(r"^(- |\d+\. )", line):
            flush()
            ordered = bool(re.match(r"^\d+\. ", line))
            tag = "ol" if ordered else "ul"
            pattern = r"^\d+\. " if ordered else r"^- "
            parts.append("<" + tag + ">")
            while i < len(lines) and re.match(pattern, lines[i]):
                parts.append("<li>" + inline(re.sub(pattern, "", lines[i])) + "</li>")
                i += 1
            parts.append("</" + tag + ">")
            continue
        elif line.startswith("> "):
            flush()
            parts.append("<blockquote>" + inline(line[2:]) + "</blockquote>")
        elif not line.strip():
            flush()
        else:
            paragraph.append(line)
        i += 1
    flush()
    return '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + html.escape(title) + '</title><style>' + CSS + '</style></head><body><main>' + "\n".join(parts) + '</main></body></html>\n'
