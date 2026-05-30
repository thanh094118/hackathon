from __future__ import annotations

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))



import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping

import joblib
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from src.features.feature_extractor import FeatureExtractor
from src.ml.config import MLArtifactPaths


LABEL_COLUMN_PATTERN = re.compile(r"^\d+\s+-\s+")
TYPE_PRIORITY = ["path_traversal", "sqli", "xss", "scanning"]
TYPE_KEYWORDS = {
    "path_traversal": ["path traversal", "traversal", "directory traversal"],
    "sqli": ["sql injection", "sqli", "sql"],
    "xss": ["xss", "cross site scripting", "cross-site scripting", "script"],
    "scanning": ["scanning", "scanner", "vulnerable software"],
}


def train_from_capec_dataset(
    *,
    features_csv: str | Path,
    labels_csv: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    features_path = Path(features_csv)
    labels_path = Path(labels_csv)
    artifacts = MLArtifactPaths(Path(output_dir))
    artifacts.ensure_root()

    feature_frame = pd.read_csv(features_path, low_memory=False)
    label_frame = pd.read_csv(labels_path, low_memory=False)

    if len(feature_frame) != len(label_frame):
        raise ValueError(
            f"Row count mismatch: features={len(feature_frame)} labels={len(label_frame)}"
        )

    feature_columns = _select_feature_columns(feature_frame)
    if not feature_columns:
        raise ValueError("No feature_ columns found in the feature CSV")

    x_frame = _build_feature_matrix(feature_frame, feature_columns)
    binary_target, attack_type_target = _build_targets(label_frame)

    split = _split_holdout(
        x_frame=x_frame,
        binary_target=binary_target,
        attack_type_target=attack_type_target,
    )
    x_train, x_test, binary_train, binary_test, attack_type_train, attack_type_test = split

    metrics = _evaluate_holdout_metrics(
        x_train=x_train,
        x_test=x_test,
        binary_train=binary_train,
        binary_test=binary_test,
        attack_type_train=attack_type_train,
        attack_type_test=attack_type_test,
    )

    binary_model = _build_binary_model()
    binary_model.fit(x_frame, binary_target)

    attack_type_model, attack_type_counts = _build_attack_type_model(x_frame, binary_target, attack_type_target)

    joblib.dump(binary_model, artifacts.binary_model_path)
    joblib.dump(attack_type_model, artifacts.attack_type_model_path)
    artifacts.feature_columns_path.write_text(json.dumps(feature_columns, indent=2), encoding="utf-8")

    metadata = {
        "feature_extractor_version": FeatureExtractor.FEATURE_VERSION,
        "feature_columns": feature_columns,
        "binary_classes": [str(value) for value in getattr(binary_model, "classes_", [])],
        "attack_type_classes": [str(value) for value in getattr(attack_type_model, "classes_", [])],
        "binary_target_counts": _count_values(binary_target),
        "attack_type_target_counts": attack_type_counts,
        "metrics": metrics,
        "source_features_csv": str(features_path),
        "source_labels_csv": str(labels_path),
    }
    artifacts.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    artifacts.metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    return {
        "artifacts_dir": str(artifacts.root),
        "rows": len(feature_frame),
        "feature_columns": feature_columns,
        "binary_target_counts": metadata["binary_target_counts"],
        "attack_type_target_counts": attack_type_counts,
        "metrics": metrics,
    }


def _select_feature_columns(frame: pd.DataFrame) -> List[str]:
    preferred = [f"feature_{name}" for name in FeatureExtractor.feature_names() if f"feature_{name}" in frame.columns]
    fallback = sorted(
        column
        for column in frame.columns
        if column.startswith("feature_") and column not in preferred and column not in {"feature_names", "feature_version"}
    )
    return preferred + fallback


def _build_feature_matrix(frame: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    matrix = frame.reindex(columns=feature_columns).copy()
    for column in feature_columns:
        matrix[column] = pd.to_numeric(matrix[column], errors="coerce").fillna(0.0)
    return matrix


def _build_targets(frame: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    label_columns = [column for column in frame.columns if LABEL_COLUMN_PATTERN.match(str(column).strip())]
    if not label_columns:
        raise ValueError("No CAPEC label columns found")

    label_values = frame[label_columns].apply(pd.to_numeric, errors="coerce").fillna(0).astype(int)
    attack_columns = [column for column in label_columns if not _is_normal_label(column)]
    if not attack_columns:
        raise ValueError("No attack label columns found")

    binary_target = label_values[attack_columns].gt(0).any(axis=1).astype(int)
    attack_type_target = pd.Series(["unknown"] * len(frame), index=frame.index, dtype="string")

    column_type_map = {column: _column_to_attack_type(column) for column in attack_columns}
    for attack_type in TYPE_PRIORITY:
        columns = [column for column, mapped in column_type_map.items() if mapped == attack_type]
        if not columns:
            continue
        matched = label_values[columns].gt(0).any(axis=1)
        attack_type_target = attack_type_target.mask(matched & (attack_type_target == "unknown"), attack_type)

    return binary_target, attack_type_target


def _build_binary_model() -> Pipeline:
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    solver="lbfgs",
                ),
            ),
        ]
    )


def _build_attack_type_model(
    x_frame: pd.DataFrame,
    binary_target: pd.Series,
    attack_type_target: pd.Series,
) -> tuple[Any, Dict[str, int]]:
    attack_mask = binary_target.astype(bool)
    attack_frame = x_frame.loc[attack_mask]
    attack_labels = attack_type_target.loc[attack_mask]
    counts = _count_values(attack_labels)

    if attack_frame.empty:
        model = DummyClassifier(strategy="most_frequent")
        model.fit(x_frame, attack_type_target)
        return model, counts

    if attack_labels.nunique() < 2:
        model = DummyClassifier(strategy="most_frequent")
        model.fit(attack_frame, attack_labels)
        return model, counts

    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    solver="lbfgs",
                ),
            ),
        ]
    )
    model.fit(attack_frame, attack_labels)
    return model, counts


def _split_holdout(
    *,
    x_frame: pd.DataFrame,
    binary_target: pd.Series,
    attack_type_target: pd.Series,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series, pd.Series]:
    try:
        return train_test_split(
            x_frame,
            binary_target,
            attack_type_target,
            test_size=0.2,
            random_state=42,
            stratify=binary_target,
        )
    except ValueError:
        return train_test_split(
            x_frame,
            binary_target,
            attack_type_target,
            test_size=0.2,
            random_state=42,
            stratify=None,
        )


def _evaluate_holdout_metrics(
    *,
    x_train: pd.DataFrame,
    x_test: pd.DataFrame,
    binary_train: pd.Series,
    binary_test: pd.Series,
    attack_type_train: pd.Series,
    attack_type_test: pd.Series,
) -> Dict[str, Any]:
    binary_model = _build_binary_model()
    binary_model.fit(x_train, binary_train)

    binary_predictions = binary_model.predict(x_test)
    binary_precision, binary_recall, binary_f1, _ = precision_recall_fscore_support(
        binary_test,
        binary_predictions,
        average="binary",
        zero_division=0,
    )

    metrics: Dict[str, Any] = {
        "binary": {
            "accuracy": round(float(accuracy_score(binary_test, binary_predictions)), 6),
            "precision": round(float(binary_precision), 6),
            "recall": round(float(binary_recall), 6),
            "f1": round(float(binary_f1), 6),
            "test_samples": int(len(binary_test)),
            "positive_samples": int(binary_test.sum()),
        },
    }

    attack_mask_train = binary_train.astype(bool)
    attack_mask_test = binary_test.astype(bool)
    attack_test_count = int(attack_mask_test.sum())

    if not attack_mask_train.any() or not attack_mask_test.any():
        metrics["attack_type"] = {
            "accuracy": 0.0,
            "precision_weighted": 0.0,
            "recall_weighted": 0.0,
            "f1_weighted": 0.0,
            "test_samples": attack_test_count,
            "positive_samples": int(attack_mask_train.sum()),
        }
        return metrics

    attack_model = _build_attack_type_model(
        x_frame=x_train,
        binary_target=binary_train,
        attack_type_target=attack_type_train,
    )[0]

    attack_predictions = attack_model.predict(x_test.loc[attack_mask_test])
    attack_truth = attack_type_test.loc[attack_mask_test]
    attack_precision, attack_recall, attack_f1, _ = precision_recall_fscore_support(
        attack_truth,
        attack_predictions,
        average="weighted",
        zero_division=0,
    )

    metrics["attack_type"] = {
        "accuracy": round(float(accuracy_score(attack_truth, attack_predictions)), 6),
        "precision_weighted": round(float(attack_precision), 6),
        "recall_weighted": round(float(attack_recall), 6),
        "f1_weighted": round(float(attack_f1), 6),
        "test_samples": attack_test_count,
        "positive_samples": int(attack_mask_train.sum()),
    }
    return metrics


def _column_to_attack_type(column: str) -> str:
    lowered = column.lower()
    for attack_type, keywords in TYPE_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return attack_type
    return "unknown"


def _is_normal_label(column: str) -> bool:
    lowered = column.lower()
    return lowered.startswith("000") or "normal" in lowered


def _count_values(values: pd.Series) -> Dict[str, int]:
    return dict(Counter(str(value) for value in values if str(value)))


def _cli() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Train CAPEC binary + attack-type models from feature and label CSVs")
    parser.add_argument("--features-csv", required=True, help="Path to features CSV (exports/feature_results/*.csv)")
    parser.add_argument("--labels-csv", required=True, help="Path to CAPEC labels CSV")
    parser.add_argument("--output-dir", required=True, help="Directory to write model artifacts")
    args = parser.parse_args()

    try:
        summary = train_from_capec_dataset(
            features_csv=Path(args.features_csv), labels_csv=Path(args.labels_csv), output_dir=Path(args.output_dir)
        )
        print(json.dumps(summary, indent=2))
        return 0
    except Exception as exc:  # pragma: no cover - CLI error path
        print(f"Training failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(_cli())