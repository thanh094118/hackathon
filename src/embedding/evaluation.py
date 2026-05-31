from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, normalize

from src.features.embedding_engine import EmbeddingEngine


LABEL_COLUMN_PATTERN = re.compile(r"^\d+\s+-\s+")

METHOD_CHOICES = (
    "char_tfidf",
    "word_tfidf",
    "numeric_features",
    "hybrid_tfidf_numeric",
    "sentence_transformer",
)

DEFAULT_METHODS = (
    "char_tfidf",
    "word_tfidf",
    "numeric_features",
    "hybrid_tfidf_numeric",
)

SEARCH_BACKENDS = ("local", "mongodb")

ATTACK_TYPE_PRIORITY = [
    "path_traversal",
    "sqli",
    "xss",
    "command_injection",
    "scanning",
    "protocol_manipulation",
    "request_smuggling",
    "input_manipulation",
]

ATTACK_TYPE_KEYWORDS = {
    "path_traversal": ["path traversal", "traversal", "directory traversal"],
    "sqli": ["sql injection", "sqli", "sql"],
    "xss": ["xss", "cross site scripting", "cross-site scripting", "script"],
    "command_injection": ["command injection", "os command injection"],
    "scanning": ["scanning", "scanner", "vulnerable software", "dictionary-based"],
    "protocol_manipulation": ["protocol manipulation", "http verb tampering"],
    "request_smuggling": ["request smuggling", "response splitting"],
    "input_manipulation": ["input data manipulation"],
}

NON_NUMERIC_FEATURE_COLUMNS = {"feature_names", "feature_version"}


@dataclass(frozen=True)
class MethodBuildResult:
    name: str
    matrix: Any
    model_artifact: Any
    metadata: Dict[str, Any]
    build_seconds: float


@dataclass(frozen=True)
class MongoVectorSearchConfig:
    uri: str
    database_name: str = "security_logs"
    collection_prefix: str = "embedding_eval_vectors"
    index_name: str = "vector_index"
    vector_path: str = "embedding"
    num_candidates: int = 100
    insert_batch_size: int = 1000
    create_index: bool = False
    index_wait_seconds: int = 120
    max_dimensions: int = 4096
    similarity: str = "cosine"
    run_id: Optional[str] = None


def build_embedding_text(row: Mapping[str, Any]) -> str:
    """
    Build a stable security-oriented text representation from extracted data.

    This intentionally uses normalized request fields as the main semantic
    input and keeps numeric features outside the text embedding.
    """
    method = _clean_text(row.get("normalized_method") or row.get("http_method"))
    uri = _clean_text(row.get("normalized_uri") or row.get("uri"))
    query = _clean_text(row.get("normalized_query_string") or row.get("query_string"))
    user_agent = _clean_text(row.get("normalized_user_agent") or row.get("user_agent"))
    raw_url = _clean_text(row.get("raw_uri") or row.get("original_url"))
    decode_depth = _clean_text(row.get("decode_depth"))

    parts = []
    if method:
        parts.append(f"method={method}")
    if uri:
        parts.append(f"path={uri}")
    if query:
        parts.append(f"query={query}")
    if user_agent:
        parts.append(f"user_agent={user_agent}")
    if raw_url and raw_url != uri and raw_url != f"{uri}?{query}":
        parts.append(f"raw_url={raw_url}")
    if decode_depth and decode_depth not in {"0", "0.0"}:
        parts.append(f"decode_depth={decode_depth}")

    if parts:
        return " | ".join(parts)

    fallback = _clean_text(row.get("normalized_request") or row.get("raw_log"))
    return fallback or ""


def run_embedding_evaluation(
    *,
    features_csv: str | Path,
    output_dir: str | Path,
    labels_csv: str | Path | None = None,
    label_offset: int = 0,
    methods: Sequence[str] = DEFAULT_METHODS,
    k_values: Sequence[int] = (1, 5, 10),
    corpus_sample_size: int = 5000,
    query_sample_size: int = 500,
    random_state: int = 42,
    sentence_transformer_model: str = "all-MiniLM-L6-v2",
    max_tfidf_features: int = 50000,
    save_vectors: bool = False,
    allow_partial_features: bool = False,
    search_backend: str = "local",
    mongodb_config: Optional[MongoVectorSearchConfig] = None,
) -> Dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if search_backend not in SEARCH_BACKENDS:
        raise ValueError(f"Unsupported search backend: {search_backend}")
    if search_backend == "mongodb" and mongodb_config is None:
        raise ValueError("mongodb_config is required when search_backend='mongodb'")

    started = time.perf_counter()
    features_path = Path(features_csv)
    feature_frame = pd.read_csv(features_path, low_memory=False)
    if feature_frame.empty:
        raise ValueError(f"Feature CSV is empty: {features_path}")

    feature_frame = feature_frame.reset_index(drop=True)
    pipeline_counts = infer_pipeline_stage_counts(features_path)
    if pipeline_counts and not allow_partial_features:
        expected_rows = pipeline_counts.get("preprocessed_requests")
        if expected_rows is not None and int(expected_rows) != len(feature_frame):
            raise ValueError(
                "Feature CSV appears incomplete: "
                f"features={len(feature_frame)} preprocessed_requests={expected_rows}. "
                "Re-run the extraction pipeline, or pass --allow-partial-features "
                "if this partial file is intentional."
            )

    feature_frame["source_row_index"] = np.arange(label_offset, label_offset + len(feature_frame))
    feature_frame["embedding_text"] = [
        build_embedding_text(record)
        for record in feature_frame.to_dict(orient="records")
    ]

    labels = _load_or_derive_labels(
        feature_frame=feature_frame,
        labels_csv=Path(labels_csv) if labels_csv else None,
        label_offset=label_offset,
    )
    feature_frame["binary_label"] = labels["binary_label"].values
    feature_frame["attack_type_label"] = labels["attack_type_label"].values

    valid_frame = feature_frame[
        feature_frame["embedding_text"].astype(str).str.len().gt(0)
        & feature_frame["attack_type_label"].astype(str).str.len().gt(0)
        & feature_frame["attack_type_label"].ne("unknown")
    ].copy()
    if valid_frame.empty:
        raise ValueError("No rows with non-empty embedding_text and usable labels were found")

    rng = np.random.default_rng(random_state)
    corpus_indices = _stratified_sample_indices(
        labels=valid_frame["attack_type_label"].astype(str).to_numpy(),
        max_count=corpus_sample_size,
        rng=rng,
    )
    corpus_frame = valid_frame.iloc[corpus_indices].reset_index(drop=True)

    query_indices = _stratified_sample_indices(
        labels=corpus_frame["attack_type_label"].astype(str).to_numpy(),
        max_count=query_sample_size,
        rng=rng,
    )
    if not len(query_indices):
        raise ValueError("No query rows available after sampling")

    k_values = sorted({int(k) for k in k_values if int(k) > 0})
    if not k_values:
        raise ValueError("At least one positive k value is required")

    method_results: Dict[str, Any] = {}
    mongodb_run_id = None
    if search_backend == "mongodb":
        mongodb_run_id = (
            mongodb_config.run_id
            if mongodb_config and mongodb_config.run_id
            else _default_mongodb_run_id(features_path=features_path, output_path=output_path)
        )

    for method in methods:
        if method not in METHOD_CHOICES:
            raise ValueError(f"Unsupported embedding method: {method}")

        build_result = _build_method_matrix(
            method=method,
            corpus_frame=corpus_frame,
            sentence_transformer_model=sentence_transformer_model,
            max_tfidf_features=max_tfidf_features,
        )

        method_error: Optional[str] = None
        mongodb_info: Dict[str, Any] = {}
        if search_backend == "mongodb":
            assert mongodb_config is not None
            assert mongodb_run_id is not None
            dimensions = int(build_result.metadata.get("dimensions") or _matrix_dimensions(build_result.matrix))
            if dimensions > int(mongodb_config.max_dimensions):
                method_error = (
                    f"Method '{method}' produced {dimensions} dimensions, above "
                    f"--mongodb-max-dimensions={mongodb_config.max_dimensions}. "
                    "Use numeric_features/sentence_transformer, lower --max-tfidf-features, "
                    "or raise the limit if your MongoDB vector index supports it."
                )
                metrics = _empty_metrics(query_count=len(query_indices))
            else:
                metrics, mongodb_info = evaluate_mongodb_vector_search(
                    matrix=build_result.matrix,
                    corpus_frame=corpus_frame,
                    query_positions=query_indices,
                    k_values=k_values,
                    method=method,
                    method_metadata=build_result.metadata,
                    config=mongodb_config,
                    run_id=mongodb_run_id,
                )
        else:
            metrics = evaluate_retrieval(
                matrix=build_result.matrix,
                labels=corpus_frame["attack_type_label"].astype(str).to_numpy(),
                query_positions=query_indices,
                k_values=k_values,
            )

        method_output_dir = output_path / "models" / method
        method_output_dir.mkdir(parents=True, exist_ok=True)
        _save_method_artifacts(
            method_output_dir=method_output_dir,
            build_result=build_result,
            metrics=metrics,
            save_vectors=save_vectors,
        )

        method_results[method] = {
            "build_seconds": build_result.build_seconds,
            "metadata": build_result.metadata,
            "metrics": metrics,
            "search_backend": "mongodb_vector_search" if search_backend == "mongodb" else "local_cosine",
        }
        if method_error:
            method_results[method]["error"] = method_error
        if mongodb_info:
            method_results[method]["mongodb"] = mongodb_info

    primary_metric = f"mrr@{max(k_values)}"
    best_method = _choose_best_method(method_results, primary_metric=primary_metric)

    summary = {
        "features_csv": str(features_path),
        "labels_csv": str(labels_csv) if labels_csv else None,
        "label_offset": label_offset,
        "row_count": int(len(feature_frame)),
        "pipeline_stage_counts": pipeline_counts,
        "valid_labeled_rows": int(len(valid_frame)),
        "corpus_rows": int(len(corpus_frame)),
        "query_rows": int(len(query_indices)),
        "search_backend": "mongodb_vector_search" if search_backend == "mongodb" else "local_cosine",
        "mongodb_run_id": mongodb_run_id,
        "methods": method_results,
        "primary_metric": primary_metric,
        "best_method": best_method,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
    }

    _write_outputs(
        output_path=output_path,
        summary=summary,
        corpus_frame=corpus_frame,
        query_indices=query_indices,
    )
    return summary


def infer_pipeline_stage_counts(features_csv: str | Path) -> Dict[str, int]:
    """
    Infer sibling pipeline stage counts from a feature_results CSV path.

    This catches interrupted runs where the earlier JSONL stages completed but
    the large feature CSV was only partially written.
    """
    feature_path = Path(features_csv)
    if feature_path.parent.name != "feature_results":
        return {}

    run_dir = feature_path.parent.parent
    file_name = feature_path.name
    suffix = "_features.csv"
    if not file_name.endswith(suffix):
        return {}

    prefix = file_name[: -len(suffix)]
    candidates = {
        "raw_lines": run_dir / "collector_results" / f"{prefix}_raw_lines.jsonl",
        "parsed_logs": run_dir / "parser_results" / f"{prefix}_parsed_logs.jsonl",
        "normalized_logs": run_dir / "normalizer_results" / f"{prefix}_normalized_logs.jsonl",
        "preprocessed_requests": run_dir / "preprocessor_results" / f"{prefix}_preprocessed_requests.jsonl",
    }

    counts: Dict[str, int] = {}
    for key, path in candidates.items():
        if path.exists():
            counts[key] = _count_text_lines(path)
    return counts


def evaluate_retrieval(
    *,
    matrix: Any,
    labels: np.ndarray,
    query_positions: Sequence[int],
    k_values: Sequence[int],
) -> Dict[str, Any]:
    labels = np.asarray(labels, dtype=object)
    k_values = sorted({int(k) for k in k_values if int(k) > 0})
    max_k = max(k_values)

    query_metrics: List[Dict[str, Any]] = []
    for query_pos in query_positions:
        query_label = str(labels[int(query_pos)])
        relevant_mask = labels == query_label
        relevant_mask[int(query_pos)] = False
        total_relevant = int(np.sum(relevant_mask))
        if total_relevant <= 0:
            continue

        similarities = _cosine_scores(matrix, int(query_pos))
        similarities[int(query_pos)] = -np.inf
        ranked = _top_k_indices(similarities, max_k)
        relevance = relevant_mask[ranked].astype(int)

        row: Dict[str, Any] = {"label": query_label, "total_relevant": total_relevant}
        for k in k_values:
            rel_at_k = relevance[:k]
            hit_count = int(np.sum(rel_at_k))
            row[f"precision@{k}"] = hit_count / k
            row[f"recall@{k}"] = hit_count / total_relevant
            row[f"hit@{k}"] = 1.0 if hit_count else 0.0
            row[f"mrr@{k}"] = _mrr(rel_at_k)
            row[f"ndcg@{k}"] = _ndcg(rel_at_k, total_relevant, k)
        query_metrics.append(row)

    if not query_metrics:
        return _empty_metrics(query_count=len(query_positions))

    return _summarize_query_metrics(
        query_metrics=query_metrics,
        query_count=len(query_positions),
    )


def evaluate_mongodb_vector_search(
    *,
    matrix: Any,
    corpus_frame: pd.DataFrame,
    query_positions: Sequence[int],
    k_values: Sequence[int],
    method: str,
    method_metadata: Mapping[str, Any],
    config: MongoVectorSearchConfig,
    run_id: str,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Evaluate retrieval through MongoDB Atlas $vectorSearch.

    The local matrix is still used as the source of query/corpus vectors, but
    nearest-neighbor ranking is delegated to MongoDB so latency and approximate
    vector-search behavior are measured in the same path used by the dashboard.
    """
    k_values = sorted({int(k) for k in k_values if int(k) > 0})
    max_k = max(k_values)
    dimensions = int(method_metadata.get("dimensions") or _matrix_dimensions(matrix))
    collection_name = _mongodb_eval_collection_name(
        config=config,
        run_id=run_id,
        method=method,
        dimensions=dimensions,
    )

    client = None
    started = time.perf_counter()
    try:
        client, collection = _connect_mongodb_collection(config, collection_name)
        collection.delete_many({})
        upload_seconds = _upload_mongodb_eval_documents(
            collection=collection,
            matrix=matrix,
            corpus_frame=corpus_frame,
            config=config,
            run_id=run_id,
            method=method,
        )

        index_info = _ensure_mongodb_vector_index(
            collection=collection,
            config=config,
            dimensions=dimensions,
        )
        if config.create_index and config.index_wait_seconds > 0:
            index_info.update(_wait_for_mongodb_vector_search(
                collection=collection,
                matrix=matrix,
                config=config,
                timeout_seconds=config.index_wait_seconds,
            ))

        labels = corpus_frame["attack_type_label"].astype(str).to_numpy()
        query_metrics: List[Dict[str, Any]] = []
        for query_pos in query_positions:
            query_pos = int(query_pos)
            query_label = str(labels[query_pos])
            relevant_mask = labels == query_label
            relevant_mask[query_pos] = False
            total_relevant = int(np.sum(relevant_mask))
            if total_relevant <= 0:
                continue

            query_vector = _matrix_row_to_vector(matrix, query_pos)
            rows, latency_ms = _run_mongodb_vector_query_with_retry(
                collection=collection,
                query_vector=query_vector,
                config=config,
                limit=max_k + 1,
                timeout_seconds=max(0, int(config.index_wait_seconds)),
            )
            relevance = _mongodb_relevance_vector(
                rows=rows,
                query_pos=query_pos,
                query_label=query_label,
                max_k=max_k,
            )

            row: Dict[str, Any] = {
                "label": query_label,
                "total_relevant": total_relevant,
                "latency_ms": latency_ms,
            }
            for k in k_values:
                rel_at_k = relevance[:k]
                hit_count = int(np.sum(rel_at_k))
                row[f"precision@{k}"] = hit_count / k
                row[f"recall@{k}"] = hit_count / total_relevant
                row[f"hit@{k}"] = 1.0 if hit_count else 0.0
                row[f"mrr@{k}"] = _mrr(rel_at_k)
                row[f"ndcg@{k}"] = _ndcg(rel_at_k, total_relevant, k)
            query_metrics.append(row)

        metrics = (
            _summarize_query_metrics(query_metrics=query_metrics, query_count=len(query_positions))
            if query_metrics
            else _empty_metrics(query_count=len(query_positions))
        )
        info = {
            "database": config.database_name,
            "collection": collection_name,
            "index": config.index_name,
            "vector_path": config.vector_path,
            "dimensions": dimensions,
            "num_candidates": max(int(config.num_candidates), max_k + 1),
            "document_count": int(len(corpus_frame)),
            "upload_seconds": upload_seconds,
            "prepare_seconds": round(time.perf_counter() - started, 6),
            **index_info,
        }
        return metrics, info
    finally:
        if client is not None:
            client.close()


def _empty_metrics(*, query_count: int) -> Dict[str, Any]:
    return {
        "evaluated_queries": 0,
        "skipped_queries": int(query_count),
        "overall": {},
        "by_label": {},
    }


def _summarize_query_metrics(
    *,
    query_metrics: Sequence[Mapping[str, Any]],
    query_count: int,
) -> Dict[str, Any]:
    metrics_frame = pd.DataFrame(query_metrics)
    metric_columns = [column for column in metrics_frame.columns if "@" in column]
    overall = {
        column: round(float(pd.to_numeric(metrics_frame[column], errors="coerce").mean()), 6)
        for column in metric_columns
    }

    if "latency_ms" in metrics_frame.columns:
        latency = pd.to_numeric(metrics_frame["latency_ms"], errors="coerce").dropna().to_numpy(dtype=float)
        if len(latency):
            overall.update(
                {
                    "latency_ms_mean": round(float(np.mean(latency)), 3),
                    "latency_ms_p50": round(float(np.percentile(latency, 50)), 3),
                    "latency_ms_p95": round(float(np.percentile(latency, 95)), 3),
                    "latency_ms_max": round(float(np.max(latency)), 3),
                }
            )

    by_label: Dict[str, Dict[str, Any]] = {}
    for label, group in metrics_frame.groupby("label"):
        label_metrics: Dict[str, Any] = {
            "queries": int(len(group)),
            **{
                column: round(float(pd.to_numeric(group[column], errors="coerce").mean()), 6)
                for column in metric_columns
            },
        }
        if "latency_ms" in group.columns:
            latency = pd.to_numeric(group["latency_ms"], errors="coerce").dropna().to_numpy(dtype=float)
            if len(latency):
                label_metrics["latency_ms_mean"] = round(float(np.mean(latency)), 3)
        by_label[str(label)] = label_metrics

    return {
        "evaluated_queries": int(len(metrics_frame)),
        "skipped_queries": int(query_count - len(metrics_frame)),
        "overall": overall,
        "by_label": by_label,
    }


def _build_method_matrix(
    *,
    method: str,
    corpus_frame: pd.DataFrame,
    sentence_transformer_model: str,
    max_tfidf_features: int,
) -> MethodBuildResult:
    texts = corpus_frame["embedding_text"].astype(str).tolist()
    started = time.perf_counter()

    if method == "char_tfidf":
        vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            lowercase=False,
            max_features=max_tfidf_features,
        )
        matrix = vectorizer.fit_transform(texts)
        artifact = {"vectorizer": vectorizer}
        metadata = {
            "type": "tfidf",
            "analyzer": "char_wb",
            "ngram_range": [3, 5],
            "dimensions": int(matrix.shape[1]),
        }

    elif method == "word_tfidf":
        vectorizer = TfidfVectorizer(
            analyzer="word",
            token_pattern=r"(?u)[^\s|]+",
            ngram_range=(1, 2),
            lowercase=False,
            max_features=max_tfidf_features,
        )
        matrix = vectorizer.fit_transform(texts)
        artifact = {"vectorizer": vectorizer}
        metadata = {
            "type": "tfidf",
            "analyzer": "word",
            "ngram_range": [1, 2],
            "dimensions": int(matrix.shape[1]),
        }

    elif method == "numeric_features":
        matrix, scaler, feature_columns = _build_numeric_matrix(corpus_frame)
        artifact = {"scaler": scaler, "feature_columns": feature_columns}
        metadata = {
            "type": "numeric_feature_vector",
            "feature_columns": feature_columns,
            "dimensions": int(matrix.shape[1]),
        }

    elif method == "hybrid_tfidf_numeric":
        vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            lowercase=False,
            max_features=max_tfidf_features,
        )
        text_matrix = vectorizer.fit_transform(texts)
        numeric_matrix, scaler, feature_columns = _build_numeric_matrix(corpus_frame)
        matrix = sparse.hstack(
            [
                text_matrix.multiply(0.75),
                sparse.csr_matrix(numeric_matrix * 0.25),
            ],
            format="csr",
        )
        matrix = normalize(matrix, norm="l2", copy=False)
        artifact = {
            "vectorizer": vectorizer,
            "scaler": scaler,
            "feature_columns": feature_columns,
            "text_weight": 0.75,
            "numeric_weight": 0.25,
        }
        metadata = {
            "type": "hybrid_char_tfidf_numeric",
            "text_dimensions": int(text_matrix.shape[1]),
            "numeric_dimensions": int(numeric_matrix.shape[1]),
            "dimensions": int(matrix.shape[1]),
            "feature_columns": feature_columns,
            "text_weight": 0.75,
            "numeric_weight": 0.25,
        }

    elif method == "sentence_transformer":
        engine = EmbeddingEngine(sentence_transformer_model)
        embeddings = np.asarray(engine.get_embeddings(texts), dtype=np.float32)
        matrix = normalize(embeddings, norm="l2", copy=False)
        artifact = None
        metadata = {
            "type": "sentence_transformer",
            "model_name": sentence_transformer_model,
            "dimensions": int(matrix.shape[1]) if matrix.ndim == 2 else 0,
        }

    else:
        raise ValueError(f"Unsupported embedding method: {method}")

    return MethodBuildResult(
        name=method,
        matrix=matrix,
        model_artifact=artifact,
        metadata=metadata,
        build_seconds=round(time.perf_counter() - started, 6),
    )


def _build_numeric_matrix(corpus_frame: pd.DataFrame) -> tuple[np.ndarray, StandardScaler, List[str]]:
    feature_columns = _select_numeric_feature_columns(corpus_frame)
    if not feature_columns:
        raise ValueError("No numeric feature_* columns found")

    values = corpus_frame.reindex(columns=feature_columns).copy()
    for column in feature_columns:
        values[column] = pd.to_numeric(values[column], errors="coerce").fillna(0.0)

    scaler = StandardScaler()
    scaled = scaler.fit_transform(values)
    return normalize(scaled, norm="l2"), scaler, feature_columns


def _select_numeric_feature_columns(frame: pd.DataFrame) -> List[str]:
    out = []
    for column in frame.columns:
        if not str(column).startswith("feature_"):
            continue
        if column in NON_NUMERIC_FEATURE_COLUMNS:
            continue
        numeric = pd.to_numeric(frame[column], errors="coerce")
        if numeric.notna().any():
            out.append(str(column))
    return out


def _load_or_derive_labels(
    *,
    feature_frame: pd.DataFrame,
    labels_csv: Optional[Path],
    label_offset: int,
) -> pd.DataFrame:
    if labels_csv:
        label_frame = pd.read_csv(
            labels_csv,
            skiprows=range(1, label_offset + 1) if label_offset > 0 else None,
            nrows=len(feature_frame),
            low_memory=False,
        )
        if len(label_frame) != len(feature_frame):
            raise ValueError(
                "Row count mismatch after label alignment: "
                f"features={len(feature_frame)} labels={len(label_frame)}"
            )
        return _capec_targets_from_labels(label_frame)

    return _weak_targets_from_features(feature_frame)


def _capec_targets_from_labels(label_frame: pd.DataFrame) -> pd.DataFrame:
    label_columns = [
        column
        for column in label_frame.columns
        if LABEL_COLUMN_PATTERN.match(str(column).strip())
    ]
    if not label_columns:
        raise ValueError("No CAPEC label columns found in labels CSV")

    label_values = label_frame[label_columns].apply(pd.to_numeric, errors="coerce").fillna(0).astype(int)
    attack_columns = [column for column in label_columns if not _is_normal_label(column)]
    if not attack_columns:
        raise ValueError("No attack label columns found in labels CSV")

    binary_attack = label_values[attack_columns].gt(0).any(axis=1)
    attack_type = pd.Series(["normal"] * len(label_frame), index=label_frame.index, dtype="object")
    column_type_map = {column: _column_to_attack_type(column) for column in attack_columns}

    for target_type in ATTACK_TYPE_PRIORITY:
        matching_columns = [
            column for column, mapped_type in column_type_map.items()
            if mapped_type == target_type
        ]
        if not matching_columns:
            continue
        matched = label_values[matching_columns].gt(0).any(axis=1)
        attack_type = attack_type.mask(matched & binary_attack & attack_type.eq("normal"), target_type)

    attack_type = attack_type.mask(binary_attack & attack_type.eq("normal"), "other_attack")
    return pd.DataFrame(
        {
            "binary_label": np.where(binary_attack, "attack", "benign"),
            "attack_type_label": attack_type,
        }
    )


def _weak_targets_from_features(feature_frame: pd.DataFrame) -> pd.DataFrame:
    labels: List[str] = []
    for record in feature_frame.to_dict(orient="records"):
        if _truthy(record.get("feature_has_path_traversal")):
            labels.append("path_traversal")
        elif _truthy(record.get("feature_has_sql_keyword")) or _truthy(record.get("feature_has_sqli_evasion_pattern")):
            labels.append("sqli")
        elif _truthy(record.get("feature_has_xss_keyword")):
            labels.append("xss")
        elif _truthy(record.get("feature_is_scanner_user_agent")):
            labels.append("scanning")
        else:
            labels.append("normal")

    return pd.DataFrame(
        {
            "binary_label": ["benign" if label == "normal" else "attack" for label in labels],
            "attack_type_label": labels,
        }
    )


def _stratified_sample_indices(labels: np.ndarray, max_count: int, rng: np.random.Generator) -> np.ndarray:
    labels = np.asarray(labels, dtype=object)
    all_indices = np.arange(len(labels))
    if max_count <= 0 or max_count >= len(all_indices):
        return all_indices

    unique_labels = sorted({str(label) for label in labels})
    if not unique_labels:
        return np.array([], dtype=int)

    selected: List[int] = []
    base_quota = max(1, max_count // len(unique_labels))
    for label in unique_labels:
        label_indices = all_indices[labels == label]
        if not len(label_indices):
            continue
        take = min(base_quota, len(label_indices))
        selected.extend(rng.choice(label_indices, size=take, replace=False).tolist())

    remaining_capacity = max_count - len(selected)
    if remaining_capacity > 0:
        remaining = np.setdiff1d(all_indices, np.asarray(selected, dtype=int), assume_unique=False)
        if len(remaining):
            take = min(remaining_capacity, len(remaining))
            selected.extend(rng.choice(remaining, size=take, replace=False).tolist())

    return np.asarray(sorted(selected), dtype=int)


def _cosine_scores(matrix: Any, query_pos: int) -> np.ndarray:
    query_vector = matrix[query_pos]
    if sparse.issparse(matrix):
        scores = query_vector @ matrix.T
        return np.asarray(scores.toarray()).ravel()
    return np.asarray(query_vector @ matrix.T).ravel()


def _top_k_indices(scores: np.ndarray, k: int) -> np.ndarray:
    k = min(k, len(scores))
    if k <= 0:
        return np.array([], dtype=int)

    finite_count = int(np.isfinite(scores).sum())
    if finite_count <= 0:
        return np.array([], dtype=int)

    candidate_count = min(k, finite_count)
    candidate_indices = np.argpartition(-scores, candidate_count - 1)[:candidate_count]
    sorted_indices = candidate_indices[np.argsort(-scores[candidate_indices])]
    return sorted_indices[:k]


def _connect_mongodb_collection(config: MongoVectorSearchConfig, collection_name: str):
    client = _create_mongo_client(config.uri)
    client.admin.command("ping")
    return client, client[config.database_name][collection_name]


def _create_mongo_client(uri: str):
    uri = _validate_mongodb_uri(uri)
    try:
        from pymongo import MongoClient
    except ImportError as exc:
        raise RuntimeError(
            "pymongo is required for --search-backend mongodb. "
            "Install project MongoDB dependencies in the active environment."
        ) from exc

    kwargs: Dict[str, Any] = {}
    try:
        import certifi

        kwargs["tlsCAFile"] = certifi.where()
    except ImportError:
        pass
    return MongoClient(uri, **kwargs)


def _validate_mongodb_uri(uri: str) -> str:
    cleaned = str(uri or "").strip()
    invalid_placeholders = ("...", "<", ">")
    if (
        not cleaned
        or cleaned in {"mongodb://", "mongodb+srv://"}
        or any(token in cleaned for token in invalid_placeholders)
    ):
        raise ValueError(
            "Invalid MongoDB URI placeholder. Set MONGODB_URI to the real Atlas URI "
            "or remove the temporary PowerShell value so .env can be loaded."
        )
    if not (cleaned.startswith("mongodb://") or cleaned.startswith("mongodb+srv://")):
        raise ValueError("MongoDB URI must start with mongodb:// or mongodb+srv://")
    return cleaned


def _upload_mongodb_eval_documents(
    *,
    collection: Any,
    matrix: Any,
    corpus_frame: pd.DataFrame,
    config: MongoVectorSearchConfig,
    run_id: str,
    method: str,
) -> float:
    started = time.perf_counter()
    batch_size = max(1, int(config.insert_batch_size))
    documents: List[Dict[str, Any]] = []

    for corpus_pos, record in enumerate(corpus_frame.to_dict(orient="records")):
        document: Dict[str, Any] = {
            "eval_run_id": run_id,
            "method": method,
            "corpus_pos": int(corpus_pos),
            "event_id": _clean_text(record.get("event_id")),
            "source_row_index": _safe_int(record.get("source_row_index"), default=corpus_pos),
            "binary_label": _clean_text(record.get("binary_label")),
            "attack_type_label": _clean_text(record.get("attack_type_label")),
            "embedding_text": _clean_text(record.get("embedding_text")),
        }
        _set_dotted_value(document, config.vector_path, _matrix_row_to_vector(matrix, corpus_pos))
        documents.append(document)

        if len(documents) >= batch_size:
            collection.insert_many(documents, ordered=False)
            documents = []

    if documents:
        collection.insert_many(documents, ordered=False)

    return round(time.perf_counter() - started, 6)


def _ensure_mongodb_vector_index(
    *,
    collection: Any,
    config: MongoVectorSearchConfig,
    dimensions: int,
) -> Dict[str, Any]:
    index_info = {
        "index_create_requested": bool(config.create_index),
        "index_created_or_exists": False,
    }
    if not config.create_index:
        return index_info

    definition = {
        "fields": [
            {
                "type": "vector",
                "path": config.vector_path,
                "numDimensions": int(dimensions),
                "similarity": config.similarity,
            }
        ]
    }

    try:
        search_index_model = None
        try:
            from pymongo.operations import SearchIndexModel

            search_index_model = SearchIndexModel(
                definition=definition,
                name=config.index_name,
                type="vectorSearch",
            )
        except ImportError:
            search_index_model = None

        try:
            if search_index_model is None:
                raise TypeError("SearchIndexModel is unavailable")
            collection.create_search_index(model=search_index_model)
        except TypeError:
            collection.create_search_index(
                {
                    "name": config.index_name,
                    "type": "vectorSearch",
                    "definition": definition,
                }
            )
        index_info["index_created_or_exists"] = True
        return index_info
    except Exception as exc:
        message = str(exc).lower()
        if "already" in message and "exist" in message:
            index_info["index_created_or_exists"] = True
            return index_info
        raise RuntimeError(
            f"Could not create MongoDB vector search index '{config.index_name}' "
            f"on path '{config.vector_path}': {exc}"
        ) from exc


def _wait_for_mongodb_vector_search(
    *,
    collection: Any,
    matrix: Any,
    config: MongoVectorSearchConfig,
    timeout_seconds: int,
) -> Dict[str, Any]:
    deadline = time.perf_counter() + max(0, int(timeout_seconds))
    query_vector = _matrix_row_to_vector(matrix, 0)
    last_error: Optional[Exception] = None
    last_status: Optional[Dict[str, Any]] = None
    started = time.perf_counter()

    while True:
        last_status = _get_mongodb_search_index_status(collection, config.index_name)
        if last_status is not None:
            logging.info(
                "MongoDB vector index %s status=%s queryable=%s",
                config.index_name,
                last_status.get("status"),
                last_status.get("queryable"),
            )

        try:
            _run_mongodb_vector_query_with_retry(
                collection=collection,
                query_vector=query_vector,
                config=config,
                limit=1,
                timeout_seconds=0,
            )
            return {
                "index_wait_seconds": round(time.perf_counter() - started, 6),
                "index_last_status": last_status,
            }
        except Exception as exc:
            last_error = exc
            if time.perf_counter() >= deadline:
                break
            time.sleep(2.0)

    raise RuntimeError(
        f"MongoDB vector index '{config.index_name}' was not queryable within "
        f"{timeout_seconds}s. last_status={last_status}; last_error={last_error}"
    )


def _get_mongodb_search_index_status(collection: Any, index_name: str) -> Optional[Dict[str, Any]]:
    try:
        try:
            indexes = list(collection.list_search_indexes(name=index_name))
        except TypeError:
            indexes = [
                index
                for index in collection.list_search_indexes()
                if str(index.get("name")) == str(index_name)
            ]
    except Exception:
        return None

    if not indexes:
        return {
            "name": index_name,
            "exists": False,
            "status": None,
            "queryable": False,
        }

    index = dict(indexes[0])
    status = str(index.get("status") or "").upper()
    queryable = bool(index.get("queryable")) or status in {"READY", "QUERYABLE"}
    return {
        "name": str(index.get("name") or index_name),
        "exists": True,
        "status": index.get("status"),
        "queryable": queryable,
    }


def _run_mongodb_vector_query_with_retry(
    *,
    collection: Any,
    query_vector: Sequence[float],
    config: MongoVectorSearchConfig,
    limit: int,
    timeout_seconds: int,
) -> tuple[List[Dict[str, Any]], float]:
    deadline = time.perf_counter() + max(0, int(timeout_seconds))
    last_error: Optional[Exception] = None

    while True:
        try:
            return _run_mongodb_vector_query(
                collection=collection,
                query_vector=query_vector,
                config=config,
                limit=limit,
            )
        except Exception as exc:
            last_error = exc
            if not _is_mongodb_index_not_ready_error(exc) or time.perf_counter() >= deadline:
                raise
            logging.info(
                "MongoDB vector index %s is not initialized yet; retrying...",
                config.index_name,
            )
            time.sleep(2.0)


def _run_mongodb_vector_query(
    *,
    collection: Any,
    query_vector: Sequence[float],
    config: MongoVectorSearchConfig,
    limit: int,
) -> tuple[List[Dict[str, Any]], float]:
    max_limit = max(1, int(limit))
    vector_stage = {
        "index": config.index_name,
        "path": config.vector_path,
        "queryVector": [float(value) for value in query_vector],
        "numCandidates": max(int(config.num_candidates), max_limit),
        "limit": max_limit,
    }
    pipeline = [
        {"$vectorSearch": vector_stage},
        {
            "$project": {
                "_id": 0,
                "corpus_pos": 1,
                "event_id": 1,
                "source_row_index": 1,
                "attack_type_label": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
    ]

    started = time.perf_counter()
    rows = [dict(row) for row in collection.aggregate(pipeline)]
    latency_ms = (time.perf_counter() - started) * 1000.0
    return rows, round(latency_ms, 3)


def _is_mongodb_index_not_ready_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        "not initialized" in message
        or "initial_sync" in message
        or "initial sync" in message
        or ("index" in message and "initializ" in message)
        or ("index" in message and "not ready" in message)
        or ("vector index" in message and "state" in message and "initial" in message)
    )


def _mongodb_relevance_vector(
    *,
    rows: Sequence[Mapping[str, Any]],
    query_pos: int,
    query_label: str,
    max_k: int,
) -> np.ndarray:
    relevance: List[int] = []
    seen_positions = set()
    for row in rows:
        corpus_pos = _safe_int(row.get("corpus_pos"), default=-1)
        if corpus_pos == query_pos or corpus_pos in seen_positions:
            continue
        seen_positions.add(corpus_pos)
        relevance.append(1 if str(row.get("attack_type_label")) == query_label else 0)
        if len(relevance) >= max_k:
            break
    return np.asarray(relevance, dtype=int)


def _matrix_dimensions(matrix: Any) -> int:
    shape = getattr(matrix, "shape", None)
    if shape and len(shape) > 1:
        return int(shape[1])
    array = np.asarray(matrix)
    if array.ndim <= 1:
        return int(array.shape[0])
    return int(array.shape[1])


def _matrix_row_to_vector(matrix: Any, row_index: int) -> List[float]:
    row = matrix[int(row_index)]
    if sparse.issparse(row):
        values = np.asarray(row.toarray()).ravel()
    else:
        values = np.asarray(row).ravel()
    values = np.nan_to_num(values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
    return values.tolist()


def _set_dotted_value(document: Dict[str, Any], dotted_path: str, value: Any) -> None:
    parts = [part for part in str(dotted_path).split(".") if part]
    if not parts:
        raise ValueError("MongoDB vector path cannot be empty")

    target = document
    for part in parts[:-1]:
        next_target = target.get(part)
        if not isinstance(next_target, dict):
            next_target = {}
            target[part] = next_target
        target = next_target
    target[parts[-1]] = value


def _mongodb_eval_collection_name(
    *,
    config: MongoVectorSearchConfig,
    run_id: str,
    method: str,
    dimensions: int,
) -> str:
    parts = [
        _slug(config.collection_prefix, max_length=32),
        _slug(run_id, max_length=32),
        _slug(method, max_length=32),
        f"d{int(dimensions)}",
    ]
    name = "_".join(part for part in parts if part)
    if name.startswith("system."):
        name = f"eval_{name}"
    return name[:120]


def _default_mongodb_run_id(*, features_path: Path, output_path: Path) -> str:
    seed = f"{features_path.resolve()}:{output_path.resolve()}:{time.time()}"
    digest = hashlib.sha1(seed.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"eval_{time.strftime('%Y%m%d_%H%M%S')}_{digest}"


def _slug(value: Any, *, max_length: int) -> str:
    text = re.sub(r"[^A-Za-z0-9_]+", "_", str(value).strip())
    text = re.sub(r"_+", "_", text).strip("_").lower()
    return (text or "x")[:max_length]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return int(default)


def _mrr(relevance: np.ndarray) -> float:
    hits = np.flatnonzero(relevance)
    if not len(hits):
        return 0.0
    return 1.0 / float(hits[0] + 1)


def _ndcg(relevance: np.ndarray, total_relevant: int, k: int) -> float:
    if not len(relevance):
        return 0.0

    dcg = 0.0
    for idx, rel in enumerate(relevance[:k], start=1):
        if rel:
            dcg += 1.0 / math.log2(idx + 1)

    ideal_hits = min(total_relevant, k)
    if ideal_hits <= 0:
        return 0.0
    ideal_dcg = sum(1.0 / math.log2(idx + 1) for idx in range(1, ideal_hits + 1))
    return dcg / ideal_dcg if ideal_dcg else 0.0


def _choose_best_method(method_results: Mapping[str, Any], *, primary_metric: str) -> Dict[str, Any]:
    best_name: Optional[str] = None
    best_score = -1.0
    for method, result in method_results.items():
        score = float(result.get("metrics", {}).get("overall", {}).get(primary_metric, 0.0))
        if score > best_score:
            best_name = method
            best_score = score
    return {"method": best_name, "metric": primary_metric, "score": round(best_score, 6)}


def _save_method_artifacts(
    *,
    method_output_dir: Path,
    build_result: MethodBuildResult,
    metrics: Mapping[str, Any],
    save_vectors: bool,
) -> None:
    metadata = {
        "method": build_result.name,
        "build_seconds": build_result.build_seconds,
        **build_result.metadata,
    }
    (method_output_dir / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (method_output_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    if build_result.model_artifact is not None:
        joblib.dump(build_result.model_artifact, method_output_dir / "model.joblib")

    if save_vectors:
        if sparse.issparse(build_result.matrix):
            sparse.save_npz(method_output_dir / "corpus_vectors.npz", build_result.matrix)
        else:
            np.save(method_output_dir / "corpus_vectors.npy", np.asarray(build_result.matrix))


def _write_outputs(
    *,
    output_path: Path,
    summary: Mapping[str, Any],
    corpus_frame: pd.DataFrame,
    query_indices: Sequence[int],
) -> None:
    (output_path / "evaluation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (output_path / "best_method.json").write_text(
        json.dumps(summary["best_method"], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    corpus_export_columns = [
        column
        for column in [
            "source_row_index",
            "event_id",
            "binary_label",
            "attack_type_label",
            "embedding_text",
            "normalized_request",
            "raw_uri",
            "raw_log",
        ]
        if column in corpus_frame.columns
    ]
    corpus_frame[corpus_export_columns].to_csv(output_path / "embedding_corpus_sample.csv", index=False)
    corpus_frame.iloc[list(query_indices)][corpus_export_columns].to_csv(
        output_path / "embedding_query_sample.csv",
        index=False,
    )

    metrics_rows: List[Dict[str, Any]] = []
    per_label_rows: List[Dict[str, Any]] = []
    for method, result in summary["methods"].items():
        overall = result["metrics"].get("overall", {})
        metrics_rows.append({"method": method, **overall})
        for label, label_metrics in result["metrics"].get("by_label", {}).items():
            per_label_rows.append({"method": method, "label": label, **label_metrics})

    pd.DataFrame(metrics_rows).to_csv(output_path / "metrics.csv", index=False)
    pd.DataFrame(per_label_rows).to_csv(output_path / "per_label_metrics.csv", index=False)


def _count_text_lines(path: Path) -> int:
    count = 0
    with path.open("rb") as handle:
        for _line in handle:
            count += 1
    return count


def _column_to_attack_type(column: str) -> str:
    lowered = str(column).lower()
    for attack_type, keywords in ATTACK_TYPE_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return attack_type
    return "other_attack"


def _is_normal_label(column: str) -> bool:
    lowered = str(column).lower()
    return lowered.startswith("000") or "normal" in lowered


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    if text.lower() in {"nan", "none", "null"}:
        return ""
    return " ".join(text.split())


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _parse_k_values(value: str) -> List[int]:
    try:
        return [int(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--k-values must be a comma-separated list of integers") from exc


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate embedding methods for extracted web-log feature data"
    )
    parser.add_argument("--features-csv", required=True, help="Path to feature_results/*_features.csv")
    parser.add_argument("--labels-csv", default=None, help="Optional CAPEC labels CSV aligned by row order")
    parser.add_argument("--label-offset", type=int, default=0, help="Starting row offset in labels CSV")
    parser.add_argument("--output-dir", required=True, help="Directory for evaluation outputs")
    parser.add_argument(
        "--methods",
        nargs="+",
        choices=METHOD_CHOICES,
        default=list(DEFAULT_METHODS),
        help="Embedding methods to evaluate",
    )
    parser.add_argument("--k-values", type=_parse_k_values, default=[1, 5, 10])
    parser.add_argument("--corpus-sample-size", type=int, default=5000)
    parser.add_argument("--query-sample-size", type=int, default=500)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--sentence-transformer-model", default="all-MiniLM-L6-v2")
    parser.add_argument("--max-tfidf-features", type=int, default=50000)
    parser.add_argument("--save-vectors", action="store_true")
    parser.add_argument(
        "--allow-partial-features",
        action="store_true",
        help="Allow evaluation when feature CSV row count differs from sibling pipeline stage counts",
    )
    parser.add_argument(
        "--search-backend",
        choices=SEARCH_BACKENDS,
        default="local",
        help="Use local exact cosine search or MongoDB Atlas $vectorSearch for ranking",
    )
    parser.add_argument("--mongodb-uri", default=None, help="MongoDB URI; defaults to MONGODB_URI")
    parser.add_argument(
        "--mongodb-db",
        default=None,
        help="MongoDB database name; defaults to MONGODB_DB_NAME or security_logs",
    )
    parser.add_argument(
        "--mongodb-collection-prefix",
        default="embedding_eval_vectors",
        help="Prefix for generated per-run/per-method MongoDB evaluation collections",
    )
    parser.add_argument("--mongodb-index", default="vector_index", help="MongoDB vector search index name")
    parser.add_argument("--mongodb-vector-path", default="embedding", help="Vector field path in evaluation docs")
    parser.add_argument("--mongodb-num-candidates", type=int, default=100)
    parser.add_argument("--mongodb-insert-batch-size", type=int, default=1000)
    parser.add_argument(
        "--mongodb-create-index",
        action="store_true",
        help="Create a vectorSearch index for each generated evaluation collection before querying",
    )
    parser.add_argument("--mongodb-index-wait-seconds", type=int, default=120)
    parser.add_argument(
        "--mongodb-max-dimensions",
        type=int,
        default=4096,
        help="Skip MongoDB evaluation for methods above this vector dimension limit",
    )
    parser.add_argument("--mongodb-similarity", choices=["cosine", "euclidean", "dotProduct"], default="cosine")
    parser.add_argument("--mongodb-run-id", default=None, help="Optional stable run id for generated collections")
    return parser


def main() -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    args = build_cli().parse_args()
    mongodb_config = None
    if args.search_backend == "mongodb":
        mongodb_uri = args.mongodb_uri or os.getenv("MONGODB_URI")
        if not mongodb_uri:
            raise SystemExit("--search-backend mongodb requires --mongodb-uri or MONGODB_URI")
        try:
            mongodb_uri = _validate_mongodb_uri(mongodb_uri)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        mongodb_config = MongoVectorSearchConfig(
            uri=mongodb_uri,
            database_name=args.mongodb_db or os.getenv("MONGODB_DB_NAME", "security_logs"),
            collection_prefix=args.mongodb_collection_prefix,
            index_name=args.mongodb_index,
            vector_path=args.mongodb_vector_path,
            num_candidates=args.mongodb_num_candidates,
            insert_batch_size=args.mongodb_insert_batch_size,
            create_index=bool(args.mongodb_create_index),
            index_wait_seconds=args.mongodb_index_wait_seconds,
            max_dimensions=args.mongodb_max_dimensions,
            similarity=args.mongodb_similarity,
            run_id=args.mongodb_run_id,
        )

    summary = run_embedding_evaluation(
        features_csv=args.features_csv,
        labels_csv=args.labels_csv,
        label_offset=args.label_offset,
        output_dir=args.output_dir,
        methods=args.methods,
        k_values=args.k_values,
        corpus_sample_size=args.corpus_sample_size,
        query_sample_size=args.query_sample_size,
        random_state=args.random_state,
        sentence_transformer_model=args.sentence_transformer_model,
        max_tfidf_features=args.max_tfidf_features,
        save_vectors=args.save_vectors,
        allow_partial_features=args.allow_partial_features,
        search_backend=args.search_backend,
        mongodb_config=mongodb_config,
    )
    print(json.dumps(summary["best_method"], indent=2))
    print(f"[+] Wrote embedding evaluation outputs to {args.output_dir}")


if __name__ == "__main__":
    main()
