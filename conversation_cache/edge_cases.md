# Edge Cases

The Phase 1 pipeline must preserve and test these cases:

- malformed log line
- empty line
- extremely long URL
- URL with percent encoding
- double encoded payload
- path traversal payload
- SQL injection payload
- XSS payload
- command injection payload
- missing user-agent
- missing referer
- invalid HTTP method
- invalid status code
- IIS-specific field missing
- non-UTF-8 input with latin-1 fallback path
- suspicious scanner user-agent
- request containing newline-like encoded payload such as `%0a` or `%0d%0a`
- Apache/Nginx lines with unexpected trailing fields should not be silently accepted as valid Apache records.
- Nginx combined format with extra trailing custom fields should parse when core combined fields are intact.
- Nginx logs with missing core fields or field-order mismatches should become parse-error records.

Additional invariants:
- parse-error records should keep `raw_log`, parse flags, and error message fields.
- parser/preprocessor stages should not crash on malformed or unexpected records.
