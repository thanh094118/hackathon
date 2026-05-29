import json
import math
import subprocess
import sys
from pathlib import Path

import joblib
import yaml

from test_pipeline.ai_inference_pipeline import BinaryBaselineInferencePipeline
from test_pipeline.ai_input_parser import AIPreParser
from test_pipeline.run_ai_pipeline import load_pipeline_config


class FakeScaler:
    def __init__(self):
        self.last_input = None

    def transform(self, matrix):
        self.last_input = [list(row) for row in matrix]
        return self.last_input


class FakeModel:
    def __init__(self):
        self.classes_ = [0, 1]
        self.last_input = None

    def predict(self, matrix):
        self.last_input = [list(row) for row in matrix]
        return [1 for _ in matrix]

    def predict_proba(self, matrix):
        self.last_input = [list(row) for row in matrix]
        return [[0.08, 0.92] for _ in matrix]


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _build_artifacts(tmp_path: Path):
    feature_columns_path = tmp_path / "feature_columns.json"
    scaler_path = tmp_path / "scaler.joblib"
    model_path = tmp_path / "model.joblib"
    label_mapping_path = tmp_path / "label_mapping.json"
    normal_ascii_mean_path = tmp_path / "normal_ascii_mean_by_field.json"

    _write_json(
        feature_columns_path,
        [
            "request_http_method",
            "request_origin",
            "response_http_status_code",
            "response_content_length",
        ],
    )
    _write_json(label_mapping_path, {"0": "Normal", "1": "Attack"})
    _write_json(
        normal_ascii_mean_path,
        {
            "request_origin": 77.7,
            "response_http_status_message": 88.8,
        },
    )

    joblib.dump(FakeScaler(), scaler_path)
    joblib.dump(FakeModel(), model_path)

    return feature_columns_path, scaler_path, model_path, label_mapping_path, normal_ascii_mean_path


def _write_config(
    *,
    path: Path,
    feature_columns_path: Path,
    scaler_path: Path,
    model_path: Path,
    label_mapping_path: Path,
    normal_ascii_mean_path: Path,
    output_dir: Path,
    threshold: float = 0.5,
) -> None:
    payload = {
        "paths": {
            "feature_columns": str(feature_columns_path),
            "scaler": str(scaler_path),
            "model": str(model_path),
            "label_mapping": str(label_mapping_path),
            "normal_ascii_mean_by_field": str(normal_ascii_mean_path),
        },
        "runtime": {
            "output_dir": str(output_dir),
            "output_filename_template": "{input_stem}_ai_predictions.jsonl",
            "preparsed_output_filename_template": "{input_stem}_ai_preparsed.jsonl",
        },
        "params": {"threshold": float(threshold), "numeric_columns": []},
    }
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_select_feature_columns_keeps_order_and_fills_missing(tmp_path: Path):
    (
        feature_columns_path,
        scaler_path,
        model_path,
        label_mapping_path,
        normal_ascii_mean_path,
    ) = _build_artifacts(tmp_path)

    pipeline = BinaryBaselineInferencePipeline(
        feature_columns_path=feature_columns_path,
        scaler_path=scaler_path,
        model_path=model_path,
        label_mapping_path=label_mapping_path,
        normal_ascii_mean_by_field_path=normal_ascii_mean_path,
    )

    records = [
        {
            "request_http_method": "GET",
            "response_http_status_code": "200",
        }
    ]
    selected = pipeline.select_feature_columns(records)

    assert list(selected[0].keys()) == [
        "request_http_method",
        "request_origin",
        "response_http_status_code",
        "response_content_length",
    ]
    assert selected[0]["request_origin"] == ""
    assert selected[0]["response_http_status_code"] == "200"
    assert selected[0]["response_content_length"] == ""


def test_predict_runs_ascii_log1p_scaler_model_flow(tmp_path: Path):
    (
        feature_columns_path,
        scaler_path,
        model_path,
        label_mapping_path,
        normal_ascii_mean_path,
    ) = _build_artifacts(tmp_path)

    pipeline = BinaryBaselineInferencePipeline(
        feature_columns_path=feature_columns_path,
        scaler_path=scaler_path,
        model_path=model_path,
        label_mapping_path=label_mapping_path,
        normal_ascii_mean_by_field_path=normal_ascii_mean_path,
    )

    records = [
        {
            "event_id": "apache:1:abc123",
            "request_http_method": "GET",
            "response_http_status_code": 200,
        }
    ]
    predictions = pipeline.predict(records)

    assert predictions[0]["event_id"] == "apache:1:abc123"
    assert predictions[0]["prediction"] == 1
    assert predictions[0]["label"] == "Attack"
    assert predictions[0]["normal_probability"] == 0.08
    assert predictions[0]["attack_probability"] == 0.92

    expected_ascii_get = (ord("g") + ord("e") + ord("t")) / 3
    expected_ascii_200 = (ord("2") + ord("0") + ord("0")) / 3
    expected_ascii_0 = ord("0")
    expected_ascii_request_origin = 77.7
    expected_log_matrix = [
        [
            math.log1p(expected_ascii_get),
            math.log1p(expected_ascii_request_origin),
            math.log1p(expected_ascii_200),
            math.log1p(expected_ascii_0),
        ]
    ]

    assert pipeline.scaler.last_input is not None
    assert pipeline.model.last_input is not None

    for got, want in zip(pipeline.scaler.last_input[0], expected_log_matrix[0]):
        assert abs(got - want) < 1e-9

    assert pipeline.model.last_input == pipeline.scaler.last_input


def test_predict_uses_threshold_over_attack_probability(tmp_path: Path):
    (
        feature_columns_path,
        scaler_path,
        model_path,
        label_mapping_path,
        normal_ascii_mean_path,
    ) = _build_artifacts(tmp_path)

    pipeline = BinaryBaselineInferencePipeline(
        feature_columns_path=feature_columns_path,
        scaler_path=scaler_path,
        model_path=model_path,
        label_mapping_path=label_mapping_path,
        normal_ascii_mean_by_field_path=normal_ascii_mean_path,
        threshold=0.95,
    )
    records = [{"event_id": "e-th", "request_http_method": "GET", "response_http_status_code": 200}]
    predictions = pipeline.predict(records)
    assert predictions[0]["attack_probability"] == 0.92
    assert predictions[0]["prediction"] == 0
    assert predictions[0]["label"] == "Normal"


def test_ai_cli_outputs_jsonl_predictions(tmp_path: Path):
    (
        feature_columns_path,
        scaler_path,
        model_path,
        label_mapping_path,
        normal_ascii_mean_path,
    ) = _build_artifacts(tmp_path)
    config_path = tmp_path / "pipeline_configs.yml"
    output_dir = tmp_path / "outputs"

    input_path = tmp_path / "input.jsonl"
    output_path = output_dir / "input_ai_predictions.jsonl"
    preparsed_output_path = output_dir / "input_ai_preparsed.jsonl"

    _write_config(
        path=config_path,
        feature_columns_path=feature_columns_path,
        scaler_path=scaler_path,
        model_path=model_path,
        label_mapping_path=label_mapping_path,
        normal_ascii_mean_path=normal_ascii_mean_path,
        output_dir=output_dir,
    )

    input_path.write_text(
        "\n".join(
            [
                json.dumps({"event_id": "e1", "request_http_method": "GET", "response_http_status_code": 200}),
                json.dumps({"event_id": "e2", "request_http_method": "POST", "response_http_status_code": 500}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "test_pipeline.run_ai_pipeline",
            "--input",
            str(input_path),
            "--config",
            str(config_path),
        ],
        check=True,
    )

    rows = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert len(rows) == 2
    assert rows[0]["event_id"] == "e1"
    assert rows[0]["prediction"] == 1
    assert rows[0]["label"] == "Attack"
    assert "attack_probability" in rows[0]

    preparsed_rows = [
        json.loads(line)
        for line in preparsed_output_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(preparsed_rows) == 2
    assert preparsed_rows[0]["event_id"] == "e1"
    assert preparsed_rows[0]["request_http_method"] == "GET"
    assert preparsed_rows[0]["response_http_status_code"] == 200


def test_load_pipeline_config_supports_project_relative_paths(tmp_path: Path):
    _, _, _, _, normal_ascii_mean_path = _build_artifacts(tmp_path)
    config_path = tmp_path / "pipeline_configs.yml"
    _write_config(
        path=config_path,
        feature_columns_path=Path("test_pipeline/feature_columns.json"),
        scaler_path=Path("test_pipeline/scaler.joblib"),
        model_path=Path("test_pipeline/random_forest.joblib"),
        label_mapping_path=Path("test_pipeline/label_mapping.json"),
        normal_ascii_mean_path=normal_ascii_mean_path,
        output_dir=Path("outputs"),
    )

    config = load_pipeline_config(config_path)
    assert config["feature_columns"].name == "feature_columns.json"
    assert config["output_dir"].name == "outputs"
    assert config["preparsed_output_filename_template"].endswith("_ai_preparsed.jsonl")
    assert config["normal_ascii_mean_by_field"].name == "normal_ascii_mean_by_field.json"
    assert config["threshold"] == 0.5


def test_impute_missing_schema_mismatch_fields_with_normal_mean(tmp_path: Path):
    (
        feature_columns_path,
        scaler_path,
        model_path,
        label_mapping_path,
        normal_ascii_mean_path,
    ) = _build_artifacts(tmp_path)

    _write_json(
        feature_columns_path,
        [
            "request_http_method",
            "request_origin",
            "response_http_status_message",
            "response_http_status_code",
        ],
    )

    pipeline = BinaryBaselineInferencePipeline(
        feature_columns_path=feature_columns_path,
        scaler_path=scaler_path,
        model_path=model_path,
        label_mapping_path=label_mapping_path,
        normal_ascii_mean_by_field_path=normal_ascii_mean_path,
    )

    prepared = [
        {
            "request_http_method": "GET",
            "request_origin": "",
            "response_http_status_message": "-",
            "response_http_status_code": "",
        }
    ]

    matrix = pipeline.mean_ascii_encode(prepared)
    expected_get = (ord("g") + ord("e") + ord("t")) / 3
    assert abs(matrix[0][0] - expected_get) < 1e-9
    assert matrix[0][1] == 77.7
    assert matrix[0][2] == 88.8
    # core field missing should not be imputed by normal mean
    assert matrix[0][3] == 0.0


def test_pre_parser_converts_raw_nginx_record_to_ai_schema():
    raw_record = {
        "event_id": "nginx:11:5a47c4c3f169",
        "line_number": 11,
        "server_type": "nginx",
        "raw_line": '62.225.70.202 - - [19/May/2015:21:05:39 +0000] "GET /presentations/logstash-puppetconf-2012/images/nagios-sms2.png HTTP/1.0" 200 60656 "http://semicomplete.com/presentations/logstash-puppetconf-2012/" "Mozilla/5.0 (Windows NT 5.1; rv:24.0) Gecko/20100101 Firefox/24.0"',
        "parse_status": "raw",
        "parse_error": False,
        "error_message": None,
        "encoding_used": "utf-8",
        "decode_error": False,
        "had_bom": False,
        "was_continuation_merged": False,
        "physical_line_start": 11,
        "physical_line_end": 11,
    }

    parsed = AIPreParser().parse_record(raw_record)
    expected = {
        "event_id": "nginx:11:5a47c4c3f169",
        "request_http_method": "GET",
        "request_http_request": "/presentations/logstash-puppetconf-2012/images/nagios-sms2.png",
        "request_http_protocol": "HTTP/1.0",
        "request_user_agent": "Mozilla/5.0 (Windows NT 5.1; rv:24.0) Gecko/20100101 Firefox/24.0",
        "request_referer": "http://semicomplete.com/presentations/logstash-puppetconf-2012/",
        "request_host": "",
        "request_origin": "",
        "request_cookie": "",
        "request_content_type": "",
        "request_accept": "",
        "request_accept_language": "",
        "request_accept_encoding": "",
        "request_do_not_track": "",
        "request_connection": "",
        "request_body": "",
        "response_http_protocol": "",
        "response_http_status_code": 200,
        "response_http_status_message": "",
        "response_content_length": 60656,
    }

    assert parsed == expected
