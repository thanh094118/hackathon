from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MLArtifactPaths:
    root: Path
    binary_model_filename: str = "binary_model.joblib"
    attack_type_model_filename: str = "attack_type_model.joblib"
    feature_columns_filename: str = "feature_columns.json"
    metadata_filename: str = "metadata.json"
    metrics_filename: str = "metrics.json"

    @property
    def binary_model_path(self) -> Path:
        return self.root / self.binary_model_filename

    @property
    def attack_type_model_path(self) -> Path:
        return self.root / self.attack_type_model_filename

    @property
    def feature_columns_path(self) -> Path:
        return self.root / self.feature_columns_filename

    @property
    def metadata_path(self) -> Path:
        return self.root / self.metadata_filename

    @property
    def metrics_path(self) -> Path:
        return self.root / self.metrics_filename

    def ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)