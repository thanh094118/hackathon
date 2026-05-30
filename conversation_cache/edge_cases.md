# Edge Cases

- Collector read-flow supports CRLF/LF/CR physical line endings; CR-only files are split correctly.
- Continuation merge is indentation-only (space/tab prefix). Non-indented injected-looking lines are kept as separate records.
- UTF-8 BOM is stripped only from the first physical line; BOM bytes in later lines are preserved as content.
- Decode fallback to latin-1 is represented via `flags` (`decode_fallback_latin1`) and can propagate from continuation lines to the merged logical record.
- `flags` is sparse and empty by default (`[]`) when no anomaly/signal exists.
- `physical_line_range` is always present and captures merged span `[start, end]`.
- IIS parser ignores comment/header lines (`#...`) and requires `#Fields` before data lines.
- Server type detection behavior to preserve:
  - early IIS detection via `#Fields:` / `#Software:`
  - Apache vs Nginx by parser success count
  - Apache default when uncertain/empty sample
- Raw HTTP request-block text input is converted into one synthetic access-log line per block.
- Mixed text files with unmatched standalone lines continue to emit those unmatched lines as raw lines.
