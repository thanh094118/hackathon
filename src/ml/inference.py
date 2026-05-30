from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import joblib
import pandas as pd

from src.ml.config import MLArtifactPaths


class MLPredictor:
    def __init__(self, *, model_dir: str | Path, threshold: float = 0.5) -> None:
        self.artifacts = MLArtifactPaths(Path(model_dir))
        self.threshold = float(threshold)

        if not self.artifacts.binary_model_path.exists():
            raise FileNotFoundError(f"Missing binary model artifact: {self.artifacts.binary_model_path}")
        if not self.artifacts.attack_type_model_path.exists():
            raise FileNotFoundError(f"Missing attack type model artifact: {self.artifacts.attack_type_model_path}")
        if not self.artifacts.feature_columns_path.exists():
            raise FileNotFoundError(f"Missing feature column artifact: {self.artifacts.feature_columns_path}")

        self.binary_model = joblib.load(self.artifacts.binary_model_path)
        self.attack_type_model = joblib.load(self.artifacts.attack_type_model_path)
        self.feature_columns = json.loads(self.artifacts.feature_columns_path.read_text(encoding="utf-8"))

    def predict_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not records:
            return []

        x_frame = self._build_feature_frame(records)
        binary_probabilities, attack_index, normal_index = self._predict_probabilities(self.binary_model, x_frame)
        binary_predictions = (binary_probabilities[:, attack_index] >= self.threshold).astype(int)
        attack_type_predictions = self._predict_attack_types(x_frame, binary_predictions)

        enriched_records: List[Dict[str, Any]] = []
        for index, record in enumerate(records):
            attack_probability = float(binary_probabilities[index, attack_index])
            normal_probability = float(binary_probabilities[index, normal_index])
            ml_label = "attack" if binary_predictions[index] else "benign"
            ml_confidence = attack_probability if ml_label == "attack" else normal_probability
            attack_type_label, attack_type_confidence = attack_type_predictions[index]

            enriched = dict(record)
            enriched.update(
                {
                    "ml_label": ml_label,
                    "ml_confidence": round(ml_confidence, 6),
                    "ml_attack_type": attack_type_label,
                    "ml_attack_type_confidence": round(attack_type_confidence, 6),
                    "ml_normal_probability": round(normal_probability, 6),
                    "ml_attack_probability": round(attack_probability, 6),
                    "ml_should_alert": bool(binary_predictions[index]),
                }
            )
            enriched_records.append(enriched)

        return enriched_records

    def _build_feature_frame(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        frame = pd.DataFrame(records)
        selected = frame.reindex(columns=self.feature_columns).copy()
        for column in self.feature_columns:
            selected[column] = pd.to_numeric(selected[column], errors="coerce").fillna(0.0)
        return selected

    @staticmethod
    def _predict_probabilities(model: Any, x_frame: pd.DataFrame):
        probabilities = model.predict_proba(x_frame)
        classes = list(getattr(model, "classes_", []))
        attack_index = classes.index(1) if 1 in classes else len(classes) - 1
        normal_index = classes.index(0) if 0 in classes else 0
        return probabilities, attack_index, normal_index

    def _predict_attack_types(self, x_frame: pd.DataFrame, binary_predictions) -> List[tuple[str, float]]:
        attack_type_predictions: List[tuple[str, float]] = []

        if not any(binary_predictions):
            return [("unknown", 0.0) for _ in range(len(x_frame))]

        if not hasattr(self.attack_type_model, "predict_proba"):
            labels = self.attack_type_model.predict(x_frame)
            return [
                (str(label), 1.0) if binary_predictions[index] else ("unknown", 0.0)
                for index, label in enumerate(labels)
            ]

        probabilities = self.attack_type_model.predict_proba(x_frame)
        classes = list(getattr(self.attack_type_model, "classes_", []))
        for index, row_probabilities in enumerate(probabilities):
            best_index = int(row_probabilities.argmax())
            best_label = str(classes[best_index]) if classes else "unknown"
            best_confidence = float(row_probabilities[best_index])
            if not binary_predictions[index]:
                attack_type_predictions.append(("unknown", 0.0))
            else:
                attack_type_predictions.append((best_label, best_confidence))

        return attack_type_predictions