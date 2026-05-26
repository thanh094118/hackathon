from pathlib import Path


class MarkdownExporter:
    """Write markdown text to file."""

    def export(self, markdown_text: str, output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown_text, encoding="utf-8")
