# Known Issues

- `tests/test_ai_inference_pipeline.py` fails to collect/run because the `test_pipeline` module/package (which it imports) is missing from the remote repository.

Areas requiring verification:
- `event_id` consistency across artifacts.
- Output schema stability across runs.
- Malformed log preservation behavior.
- `configs/rules.yaml` loading behavior.
- Nginx custom format coverage beyond combined and combined-with-trailing-fields profiles.
- IIS parser coverage for real W3C IIS variants.
- `report.md` and `run_summary.json` count correctness.
- Generated output folder `.gitignore` behavior.

Environment note:
- Shell may print `/home/thanh/miniconda3/envs/easymocap/lib/libtinfo.so.6: no version information available`; this appears environment-specific and not project logic.
