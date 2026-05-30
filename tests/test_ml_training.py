from pathlib import Path

import json
import pandas as pd

from src.ml.inference import MLPredictor
from src.ml.training import train_from_capec_dataset


def _write_csv(path: Path, frame: pd.DataFrame) -> None:
    frame.to_csv(path, index=False)


def test_train_and_predict_roundtrip(tmp_path: Path):
    features_csv = tmp_path / "features.csv"
    labels_csv = tmp_path / "labels.csv"
    model_dir = tmp_path / "models" / "ml"

    features = pd.DataFrame(
        [
            {"feature_uri_length": 1, "feature_query_length": 0, "feature_user_agent_length": 2, "feature_param_count": 0},
            {"feature_uri_length": 50, "feature_query_length": 40, "feature_user_agent_length": 10, "feature_param_count": 3},
            {"feature_uri_length": 60, "feature_query_length": 5, "feature_user_agent_length": 4, "feature_param_count": 1},
            {"feature_uri_length": 80, "feature_query_length": 20, "feature_user_agent_length": 12, "feature_param_count": 5},
        ]
    )
    labels = pd.DataFrame(
        [
            {"000 - Normal": 1, "66 - SQL Injection": 0, "126 - Path Traversal": 0, "310 - Scanning for Vulnerable Software": 0},
            {"000 - Normal": 0, "66 - SQL Injection": 1, "126 - Path Traversal": 0, "310 - Scanning for Vulnerable Software": 0},
            {"000 - Normal": 0, "66 - SQL Injection": 0, "126 - Path Traversal": 1, "310 - Scanning for Vulnerable Software": 0},
            {"000 - Normal": 0, "66 - SQL Injection": 0, "126 - Path Traversal": 0, "310 - Scanning for Vulnerable Software": 1},
        ]
    )

    _write_csv(features_csv, features)
    _write_csv(labels_csv, labels)

    summary = train_from_capec_dataset(
        features_csv=features_csv,
        labels_csv=labels_csv,
        output_dir=model_dir,
    )

    assert summary["rows"] == 4
    assert (model_dir / "binary_model.joblib").exists()
    assert (model_dir / "attack_type_model.joblib").exists()
    assert (model_dir / "feature_columns.json").exists()
    assert (model_dir / "metrics.json").exists()
    assert (model_dir / "metadata.json").exists()

    metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
    assert "metrics" in metadata
    assert "binary" in metadata["metrics"]
    assert "attack_type" in metadata["metrics"]
    assert "accuracy" in metadata["metrics"]["binary"]
    assert "f1" in metadata["metrics"]["binary"]

    metrics = json.loads((model_dir / "metrics.json").read_text(encoding="utf-8"))
    assert "binary" in metrics
    assert "attack_type" in metrics
    assert "accuracy" in metrics["binary"]

    predictor = MLPredictor(model_dir=model_dir)
    predictions = predictor.predict_records(
        [
            {
                "feature_uri_length": 1,
                "feature_query_length": 0,
                "feature_user_agent_length": 2,
                "feature_param_count": 0,
            },
            {
                "feature_uri_length": 90,
                "feature_query_length": 18,
                "feature_user_agent_length": 15,
                "feature_param_count": 4,
            },
        ]
    )

    assert len(predictions) == 2
    assert {row["ml_label"] for row in predictions}.issubset({"benign", "attack"})
    assert all("ml_confidence" in row for row in predictions)
    assert all("ml_attack_type" in row for row in predictions)
    assert all("ml_attack_type_confidence" in row for row in predictions)
