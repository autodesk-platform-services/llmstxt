# Can you see the APS docs?  what is SSA ?
import yaml
from pathlib import Path

def convert_yaml_to_markdown(yaml_path):
    with open(yaml_path, 'r') as f:
        spec = yaml.safe_load(f)

    info = spec.get("info", {}) or {}
    title = info.get("title", yaml_path.stem)
    description = info.get("description", "No description provided.")

    markdown_lines = [
        description,
        "\n---\n",
    ]

    paths = spec.get("paths", {}) or {}
    if not isinstance(paths, dict):
        return "\n".join(markdown_lines), (title, description)

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue

            # safe to call .get() now
            summary = details.get("summary", f"{method.upper()} {path}")
            operation_desc = details.get("description", "No description provided.").strip()
            operation_id = details.get("operationId", "")
            parameters   = details.get("parameters", [])
            request_body = details.get("requestBody", {}) or {}
            responses    = details.get("responses", {}) or {}

            markdown_lines.append(f"### {summary}\n")
            markdown_lines.append(f"**Endpoint:** `{method.upper()} {path}`")
            if operation_id:
                markdown_lines.append(f"**Operation ID:** `{operation_id}`")
            markdown_lines.append("")  # blank line
            markdown_lines.append("#### Description")
            markdown_lines.append(operation_desc)
            markdown_lines.append("")

            if isinstance(parameters, list) and parameters:
                markdown_lines.append("#### Parameters")
                for param in parameters:
                    if not isinstance(param, dict):
                        continue
                    ref = param.get('$ref')
                    if ref:
                        markdown_lines.append(f"- Ref: `{ref}`")
                    else:
                        name     = param.get("name", "unknown")
                        loc      = param.get("in", "unknown")
                        req      = param.get("required", False)
                        desc     = param.get("description", "").strip()
                        markdown_lines.append(f"- `{name}` in `{loc}` (required: {req}) — {desc}")
                markdown_lines.append("")

            if isinstance(request_body, dict) and request_body:
                markdown_lines.append("#### Request Body")
                req = request_body.get("required", False)
                markdown_lines.append(f"- Required: `{req}`")
                content = request_body.get("content", {}) or {}
                if isinstance(content, dict):
                    for ctype, cinfo in content.items():
                        markdown_lines.append(f"- Content-Type: `{ctype}`")
                        schema = cinfo.get("schema", {}) if isinstance(cinfo, dict) else {}
                        ref    = schema.get("$ref", "")
                        if ref:
                            markdown_lines.append(f"  - Schema: `{ref}`")
                markdown_lines.append("")

            if isinstance(responses, dict) and responses:
                resp_lines = []
                for code, resp in responses.items():
                    if isinstance(resp, dict):
                        d = resp.get("description", "").strip()
                        if d:
                            resp_lines.append(f"- **{code}**: {d}")
                if resp_lines:
                    markdown_lines.append("#### Responses")
                    markdown_lines.extend(resp_lines)
                    markdown_lines.append("")

            markdown_lines.append("---\n")

    return "\n".join(markdown_lines), (title, description)


def combine_all_yaml_to_markdown(input_folder="yaml", output_md="llmstxt.md"):
    combined_lines = []
    # 1) Rename the heading
    summary_lines  = ["# Autodesk Platform Services APIs overview\n"]
    input_path     = Path(input_folder)

    for yaml_file in sorted(input_path.glob("*.yaml")):
        markdown, (title, description) = convert_yaml_to_markdown(yaml_file)

        # 2) Truncate description to ~200 words
        words = description.split()
        short_desc = " ".join(words[:200]) + ("…" if len(words) > 200 else "")

        # 3) Emit as a ### header + paragraph
        summary_lines.append(f"### {title}\n{short_desc}\n")
        
        combined_lines.append(f"## {title}\n")
        combined_lines.append(f"_Generated from `{yaml_file.name}`_\n")
        combined_lines.append(markdown)

    # append examples.md as before…
    examples_file = Path("examples.md")
    if examples_file.exists():
        combined_lines.append("\n# Examples\n")
        combined_lines.append(examples_file.read_text(encoding="utf-8"))

    Path(output_md).write_text(
        "\n".join(summary_lines + ["\n"] + combined_lines),
        encoding="utf-8"
    )

if __name__ == "__main__":
    combine_all_yaml_to_markdown()