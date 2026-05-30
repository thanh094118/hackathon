# Known Issues

- If dashboard dependencies are missing in the active interpreter, `from src.dashboard.app import main` or `streamlit run ...` will fail until `streamlit`/related deps are installed.
- Full repository `pytest -q` can fail in environments missing optional test prerequisites outside dashboard scope.
- Credentials that appeared in local/staged `.env` before cleanup must be rotated by the project team.
- Current workspace snapshot still includes many out-of-scope staged changes (backend/ML/data/infra), which can block clean Issue 3-only review if not cleaned first.
