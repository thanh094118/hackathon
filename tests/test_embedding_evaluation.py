import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.embedding.evaluation import (
    MongoVectorSearchConfig,
    _create_mongo_client,
    _run_mongodb_vector_query_with_retry,
    build_embedding_text,
    run_embedding_evaluation,
)


def _write_csv(path: Path, rows):
    pd.DataFrame(rows).to_csv(path, index=False)


def test_build_embedding_text_uses_normalized_security_fields():
    text = build_embedding_text(
        {
            "normalized_method": "get",
            "normalized_uri": "/login",
            "normalized_query_string": "user=admin or 1=1",
            "normalized_user_agent": "sqlmap/1.0",
            "raw_uri": "/login?user=admin%20OR%201=1",
            "decode_depth": 1,
        }
    )

    assert "method=get" in text
    assert "path=/login" in text
    assert "query=user=admin or 1=1" in text
    assert "user_agent=sqlmap/1.0" in text
    assert "raw_url=/login?user=admin%20OR%201=1" in text
    assert "decode_depth=1" in text


def test_run_embedding_evaluation_writes_metrics_and_artifacts(tmp_path: Path):
    features_csv = tmp_path / "features.csv"
    labels_csv = tmp_path / "labels.csv"
    output_dir = tmp_path / "embedding_eval"

    feature_rows = [
        {
            "event_id": "e1",
            "normalized_method": "get",
            "normalized_uri": "/",
            "normalized_query_string": "",
            "normalized_user_agent": "mozilla",
            "raw_uri": "/",
            "feature_uri_length": 1,
            "feature_query_length": 0,
            "feature_user_agent_length": 7,
            "feature_param_count": 0,
            "feature_has_sql_keyword": 0,
            "feature_has_path_traversal": 0,
            "feature_has_xss_keyword": 0,
        },
        {
            "event_id": "e2",
            "normalized_method": "get",
            "normalized_uri": "/search",
            "normalized_query_string": "q=' or 1=1",
            "normalized_user_agent": "browser",
            "raw_uri": "/search?q=%27%20or%201=1",
            "feature_uri_length": 7,
            "feature_query_length": 9,
            "feature_user_agent_length": 7,
            "feature_param_count": 1,
            "feature_has_sql_keyword": 1,
            "feature_has_path_traversal": 0,
            "feature_has_xss_keyword": 0,
        },
        {
            "event_id": "e3",
            "normalized_method": "get",
            "normalized_uri": "/item",
            "normalized_query_string": "id=1 union select password",
            "normalized_user_agent": "browser",
            "raw_uri": "/item?id=1%20union%20select%20password",
            "feature_uri_length": 5,
            "feature_query_length": 26,
            "feature_user_agent_length": 7,
            "feature_param_count": 1,
            "feature_has_sql_keyword": 1,
            "feature_has_path_traversal": 0,
            "feature_has_xss_keyword": 0,
        },
        {
            "event_id": "e4",
            "normalized_method": "get",
            "normalized_uri": "/download",
            "normalized_query_string": "file=../../etc/passwd",
            "normalized_user_agent": "browser",
            "raw_uri": "/download?file=..%2f..%2fetc%2fpasswd",
            "feature_uri_length": 9,
            "feature_query_length": 21,
            "feature_user_agent_length": 7,
            "feature_param_count": 1,
            "feature_has_sql_keyword": 0,
            "feature_has_path_traversal": 1,
            "feature_has_xss_keyword": 0,
        },
        {
            "event_id": "e5",
            "normalized_method": "get",
            "normalized_uri": "/static",
            "normalized_query_string": "path=../windows/win.ini",
            "normalized_user_agent": "browser",
            "raw_uri": "/static?path=..%2fwindows%2fwin.ini",
            "feature_uri_length": 7,
            "feature_query_length": 23,
            "feature_user_agent_length": 7,
            "feature_param_count": 1,
            "feature_has_sql_keyword": 0,
            "feature_has_path_traversal": 1,
            "feature_has_xss_keyword": 0,
        },
        {
            "event_id": "e6",
            "normalized_method": "get",
            "normalized_uri": "/about",
            "normalized_query_string": "",
            "normalized_user_agent": "mozilla",
            "raw_uri": "/about",
            "feature_uri_length": 6,
            "feature_query_length": 0,
            "feature_user_agent_length": 7,
            "feature_param_count": 0,
            "feature_has_sql_keyword": 0,
            "feature_has_path_traversal": 0,
            "feature_has_xss_keyword": 0,
        },
    ]
    label_rows = [
        {"000 - Normal": 1, "66 - SQL Injection": 0, "126 - Path Traversal": 0},
        {"000 - Normal": 0, "66 - SQL Injection": 1, "126 - Path Traversal": 0},
        {"000 - Normal": 0, "66 - SQL Injection": 1, "126 - Path Traversal": 0},
        {"000 - Normal": 0, "66 - SQL Injection": 0, "126 - Path Traversal": 1},
        {"000 - Normal": 0, "66 - SQL Injection": 0, "126 - Path Traversal": 1},
        {"000 - Normal": 1, "66 - SQL Injection": 0, "126 - Path Traversal": 0},
    ]
    _write_csv(features_csv, feature_rows)
    _write_csv(labels_csv, label_rows)

    summary = run_embedding_evaluation(
        features_csv=features_csv,
        labels_csv=labels_csv,
        output_dir=output_dir,
        methods=["char_tfidf", "numeric_features", "hybrid_tfidf_numeric"],
        k_values=[1, 2],
        corpus_sample_size=0,
        query_sample_size=0,
        random_state=7,
    )

    assert summary["row_count"] == 6
    assert summary["corpus_rows"] == 6
    assert summary["query_rows"] == 6
    assert summary["best_method"]["method"] in {"char_tfidf", "numeric_features", "hybrid_tfidf_numeric"}

    assert (output_dir / "evaluation_summary.json").exists()
    assert (output_dir / "metrics.csv").exists()
    assert (output_dir / "per_label_metrics.csv").exists()
    assert (output_dir / "embedding_corpus_sample.csv").exists()
    assert (output_dir / "models" / "char_tfidf" / "model.joblib").exists()
    assert (output_dir / "models" / "numeric_features" / "model.joblib").exists()

    stored = json.loads((output_dir / "evaluation_summary.json").read_text(encoding="utf-8"))
    assert "mrr@2" in stored["methods"]["char_tfidf"]["metrics"]["overall"]


def test_run_embedding_evaluation_rejects_partial_pipeline_feature_csv(tmp_path: Path):
    run_dir = tmp_path / "run1"
    feature_dir = run_dir / "feature_results"
    preprocessor_dir = run_dir / "preprocessor_results"
    feature_dir.mkdir(parents=True)
    preprocessor_dir.mkdir(parents=True)

    features_csv = feature_dir / "apache_sample_features.csv"
    _write_csv(
        features_csv,
        [
            {
                "event_id": "e1",
                "normalized_method": "get",
                "normalized_uri": "/",
                "feature_uri_length": 1,
            }
        ],
    )
    (preprocessor_dir / "apache_sample_preprocessed_requests.jsonl").write_text(
        '{"event_id":"e1"}\n{"event_id":"e2"}\n',
        encoding="utf-8",
    )

    try:
        run_embedding_evaluation(
            features_csv=features_csv,
            output_dir=tmp_path / "eval",
            methods=["char_tfidf"],
            k_values=[1],
        )
    except ValueError as exc:
        assert "Feature CSV appears incomplete" in str(exc)
    else:
        raise AssertionError("Expected partial feature CSV to be rejected")


class _FakeMongoCollection:
    def __init__(self, transient_failures=0):
        self.documents = []
        self.aggregate_pipelines = []
        self.transient_failures = transient_failures

    def delete_many(self, _filter):
        self.documents = []

    def insert_many(self, documents, ordered=False):
        self.documents.extend(dict(document) for document in documents)
        return object()

    def aggregate(self, pipeline):
        self.aggregate_pipelines.append(pipeline)
        if self.transient_failures > 0:
            self.transient_failures -= 1
            if self.transient_failures % 2:
                raise RuntimeError("Index vector_index not initialized")
            raise RuntimeError("cannot query vector index abc while in state INITIAL_SYNC")

        vector_stage = pipeline[0]["$vectorSearch"]
        query_vector = np.asarray(vector_stage["queryVector"], dtype=float)
        limit = int(vector_stage["limit"])

        rows = []
        for document in self.documents:
            vector = np.asarray(document["embedding"], dtype=float)
            rows.append(
                {
                    "corpus_pos": document["corpus_pos"],
                    "event_id": document["event_id"],
                    "source_row_index": document["source_row_index"],
                    "attack_type_label": document["attack_type_label"],
                    "score": float(query_vector @ vector),
                }
            )
        return sorted(rows, key=lambda row: row["score"], reverse=True)[:limit]


class _FakeMongoDatabase:
    def __init__(self, collection):
        self.collection = collection

    def __getitem__(self, _name):
        return self.collection


class _FakeMongoAdmin:
    def command(self, _name):
        return {"ok": 1}


class _FakeMongoClient:
    def __init__(self, collection):
        self.collection = collection
        self.admin = _FakeMongoAdmin()
        self.closed = False

    def __getitem__(self, _name):
        return _FakeMongoDatabase(self.collection)

    def close(self):
        self.closed = True


def test_run_embedding_evaluation_can_use_mongodb_vector_search_backend(tmp_path: Path, monkeypatch):
    features_csv = tmp_path / "features.csv"
    labels_csv = tmp_path / "labels.csv"
    output_dir = tmp_path / "embedding_eval_mongo"

    feature_rows = [
        {"event_id": "n1", "normalized_uri": "/", "feature_uri_length": 1, "feature_has_sql_keyword": 0, "feature_has_path_traversal": 0},
        {"event_id": "n2", "normalized_uri": "/home", "feature_uri_length": 5, "feature_has_sql_keyword": 0, "feature_has_path_traversal": 0},
        {"event_id": "s1", "normalized_uri": "/search", "normalized_query_string": "q=' or 1=1", "feature_uri_length": 7, "feature_has_sql_keyword": 1, "feature_has_path_traversal": 0},
        {"event_id": "s2", "normalized_uri": "/item", "normalized_query_string": "id=1 union select", "feature_uri_length": 5, "feature_has_sql_keyword": 1, "feature_has_path_traversal": 0},
        {"event_id": "p1", "normalized_uri": "/download", "normalized_query_string": "file=../../etc/passwd", "feature_uri_length": 9, "feature_has_sql_keyword": 0, "feature_has_path_traversal": 1},
        {"event_id": "p2", "normalized_uri": "/static", "normalized_query_string": "path=../win.ini", "feature_uri_length": 7, "feature_has_sql_keyword": 0, "feature_has_path_traversal": 1},
    ]
    label_rows = [
        {"000 - Normal": 1, "66 - SQL Injection": 0, "126 - Path Traversal": 0},
        {"000 - Normal": 1, "66 - SQL Injection": 0, "126 - Path Traversal": 0},
        {"000 - Normal": 0, "66 - SQL Injection": 1, "126 - Path Traversal": 0},
        {"000 - Normal": 0, "66 - SQL Injection": 1, "126 - Path Traversal": 0},
        {"000 - Normal": 0, "66 - SQL Injection": 0, "126 - Path Traversal": 1},
        {"000 - Normal": 0, "66 - SQL Injection": 0, "126 - Path Traversal": 1},
    ]
    _write_csv(features_csv, feature_rows)
    _write_csv(labels_csv, label_rows)

    collection = _FakeMongoCollection()
    client = _FakeMongoClient(collection)
    monkeypatch.setattr("src.embedding.evaluation._create_mongo_client", lambda _uri: client)

    summary = run_embedding_evaluation(
        features_csv=features_csv,
        labels_csv=labels_csv,
        output_dir=output_dir,
        methods=["numeric_features"],
        k_values=[1, 2],
        corpus_sample_size=0,
        query_sample_size=0,
        random_state=7,
        search_backend="mongodb",
        mongodb_config=MongoVectorSearchConfig(
            uri="mongodb://example.invalid",
            database_name="test_db",
            collection_prefix="embedding_eval_test",
            create_index=False,
            run_id="unit_test",
        ),
    )

    result = summary["methods"]["numeric_features"]
    assert result["search_backend"] == "mongodb_vector_search"
    assert result["mongodb"]["collection"].startswith("embedding_eval_test_unit_test")
    assert result["metrics"]["evaluated_queries"] == 6
    assert "latency_ms_mean" in result["metrics"]["overall"]
    assert len(collection.documents) == 6
    assert collection.aggregate_pipelines
    assert "$vectorSearch" in collection.aggregate_pipelines[0][0]
    assert client.closed is True


def test_mongodb_uri_placeholder_is_rejected_before_pymongo():
    try:
        _create_mongo_client("mongodb+srv://...")
    except ValueError as exc:
        assert "Invalid MongoDB URI placeholder" in str(exc)
    else:
        raise AssertionError("Expected placeholder MongoDB URI to be rejected")


def test_mongodb_vector_query_retries_while_index_initializes(monkeypatch):
    collection = _FakeMongoCollection(transient_failures=2)
    collection.documents = [
        {
            "corpus_pos": 0,
            "event_id": "e1",
            "source_row_index": 0,
            "attack_type_label": "normal",
            "embedding": [1.0, 0.0],
        }
    ]
    monkeypatch.setattr("src.embedding.evaluation.time.sleep", lambda _seconds: None)

    rows, latency_ms = _run_mongodb_vector_query_with_retry(
        collection=collection,
        query_vector=[1.0, 0.0],
        config=MongoVectorSearchConfig(uri="mongodb://example.invalid", index_name="vector_index"),
        limit=1,
        timeout_seconds=10,
    )

    assert rows[0]["event_id"] == "e1"
    assert latency_ms >= 0
    assert len(collection.aggregate_pipelines) == 3
