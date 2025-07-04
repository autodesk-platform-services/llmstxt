import requests
import re
import json
import os

# Config
JSON_URL = "https://developer.doc.config.autodesk.com/bPlouYTd/aecdatamodel_v1.json"
BASE_STATIC_URL = "https://developer.doc.autodesk.com/bPlouYTd/"
OUTPUT_FILE = "llms-graphql.txt.md"
MD_DIR = "md"
MAX_JSON_LENGTH = 400

CODE_BLOCK_RE = re.compile(r"```(.*?)```", re.DOTALL)
HTML_TAG_RE = re.compile(r'<[^>]+>')

def fetch_json(url):
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def extract_static_pages(node, pages=None):
    if pages is None:
        pages = []
    if 'source' in node:
        pages.append(BASE_STATIC_URL + node['source'])
    if 'children' in node:
        for child in node['children']:
            extract_static_pages(child, pages)
    return pages

def is_graphql_query(code):
    code_stripped = code.strip()
    if code_stripped.startswith("query") or code_stripped.startswith("mutation"):
        return True
    if re.search(r'\$[a-zA-Z_][a-zA-Z0-9_]*', code_stripped) and '{' in code_stripped and '}' in code_stripped:
        return True
    return False

def format_graphql_compact(code):
    lines = [line.strip() for line in code.splitlines() if line.strip() != '']
    compact = ' '.join(lines)
    compact = re.sub(r'\s+', ' ', compact)
    return compact.strip()

def strip_html_tags(text):
    return HTML_TAG_RE.sub('', text)

def tidy_code_block(code):
    code = strip_html_tags(code.strip())
    # Try to parse as JSON
    try:
        parsed = json.loads(code)
        compact_json = json.dumps(parsed, separators=(',', ':'))
        if len(compact_json) > MAX_JSON_LENGTH:
            return compact_json[:MAX_JSON_LENGTH] + ' ...etc'
        return compact_json
    except Exception:
        pass
    # If GraphQL, format it compactly
    if is_graphql_query(code):
        return format_graphql_compact(code)
    # Otherwise, collapse to a single line
    lines = [line.strip() for line in code.splitlines() if line.strip() != '']
    compact = ' '.join(lines)
    compact = re.sub(r'\s+', ' ', compact)
    return compact.strip()

def tidy_markdown_content(content):
    def repl(match):
        code = match.group(1)
        tidied = tidy_code_block(code)
        return f"```\n{tidied}\n```"
    return CODE_BLOCK_RE.sub(repl, content)

def extract_title_and_headings(html):
    # Simple regex-based extraction for title and h1/h2/h3
    title = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
    title = title.group(1).strip() if title else ''
    headings = re.findall(r'<h([123])[^>]*>(.*?)</h[123]>', html, re.IGNORECASE)
    return title, [(f"h{level}", re.sub('<.*?>', '', text).strip()) for level, text in headings]

def extract_description(html):
    # Find the first <p> after the first <h1> or <h2>
    h_match = re.search(r'<h[12][^>]*>.*?</h[12]>', html, re.IGNORECASE | re.DOTALL)
    if h_match:
        after_h = html[h_match.end():]
        p_match = re.search(r'<p[^>]*>(.*?)</p>', after_h, re.IGNORECASE | re.DOTALL)
        if p_match:
            desc = strip_html_tags(p_match.group(1)).strip()
            return desc
    # fallback: first <p> in the document
    p_match = re.search(r'<p[^>]*>(.*?)</p>', html, re.IGNORECASE | re.DOTALL)
    if p_match:
        desc = strip_html_tags(p_match.group(1)).strip()
        return desc
    return ''

def extract_code_blocks(html):
    # Find <pre>...</pre> and <code>...</code> blocks
    code_blocks = []
    for match in re.findall(r'<pre[^>]*>(.*?)</pre>', html, re.DOTALL):
        code_blocks.append(match)
    for match in re.findall(r'<code[^>]*>(.*?)</code>', html, re.DOTALL):
        if len(match.splitlines()) > 1 and match not in code_blocks:
            code_blocks.append(match)
    return code_blocks

def process_page(url, save_md_dir=None, fname=None):
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        html = resp.text
        title, headings = extract_title_and_headings(html)
        description = extract_description(html)
        code_blocks = extract_code_blocks(html)
        # Compose markdown
        md = []
        if title:
            md.append(f"# {title}\n\n")
        for tag, text in headings:
            if tag == "h1":
                md.append(f"# {text}\n\n")
            elif tag == "h2":
                md.append(f"## {text}\n\n")
            elif tag == "h3":
                md.append(f"### {text}\n\n")
        if description:
            md.append(f"> {description}\n\n")
        if code_blocks:
            md.append("## Code Examples\n\n")
            for code in code_blocks:
                tidied = tidy_code_block(code)
                md.append(f"```\n{tidied}\n```\n\n")
        md_str = ''.join(md)
        # Save to md_dir if requested
        if save_md_dir and fname:
            if not os.path.exists(save_md_dir):
                os.makedirs(save_md_dir)
            with open(os.path.join(save_md_dir, fname), "w", encoding="utf-8") as f:
                f.write(md_str)
        return md_str
    except Exception as e:
        return f"# {url}\n\nFailed to process: {e}\n\n"

def main():
    data = fetch_json(JSON_URL)
    static_pages = extract_static_pages(data)
    all_md = ["# Autodesk APS GraphQLDocumentation - AEC DataModel and DataExchange APIs \n"]
    file_stats = []
    total_size = 0
    for url in static_pages:
        fname = url.split('/')[-1].replace('.html', '.md')
        md = process_page(url, save_md_dir=MD_DIR, fname=fname)
        size = len(md.encode('utf-8'))
        total_size += size
        file_stats.append((fname, size))
        all_md.append(f"## {fname}\n\n{md}\n---\n\n")
    final_md = ''.join(all_md)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(final_md)
    print("File size stats:")
    for fname, size in file_stats:
        print(f"{fname}: {size} bytes")
    print(f"Total size: {total_size} bytes")
    print(f"Wrote {OUTPUT_FILE}")

if __name__ == "__main__":
    main() 