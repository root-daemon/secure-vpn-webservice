import io

import boto3
import pytest
from moto import mock_aws

from vault import create_app

BUCKET = "test-vault-bucket"


@pytest.fixture
def client():
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)
        s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        app = create_app(
            s3_client=s3,
            config={"BUCKET": BUCKET, "TESTING": True, "SESSION_COOKIE_SECURE": False},
        )
        with app.test_client() as test_client:
            test_client.s3 = s3
            yield test_client


def csrf_token(client) -> str:
    token = client.get("/api/session").get_json()["csrf_token"]
    assert token, "CSRF token missing from session bootstrap"
    return token


def upload(client, token, data: bytes, name: str):
    return client.post(
        "/api/files",
        data={"file": (io.BytesIO(data), name)},
        headers={"X-CSRF-Token": token},
        content_type="multipart/form-data",
    )


def test_health_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
    assert response.get_json()["checks"]["storage"] == "ok"


def test_health_degraded_when_storage_unreachable():
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")  # bucket never created
        app = create_app(s3_client=s3, config={"BUCKET": "missing", "TESTING": True})
        response = app.test_client().get("/health")
    assert response.status_code == 503
    assert response.get_json()["status"] == "degraded"


def test_upload_list_download_roundtrip_uses_kms(client):
    token = csrf_token(client)
    response = upload(client, token, b"top secret", "report.txt")
    assert response.status_code == 201

    head = client.s3.head_object(Bucket=BUCKET, Key="vault/report.txt")
    assert head["ServerSideEncryption"] == "aws:kms"

    names = [f["name"] for f in client.get("/api/files").get_json()["files"]]
    assert names == ["report.txt"]
    download = client.get("/files/report.txt")
    assert download.status_code == 200
    assert download.data == b"top secret"

    info = client.get("/files/report.txt/info").get_json()
    assert info["server_side_encryption"] == "aws:kms"


def test_post_without_csrf_token_rejected(client):
    response = client.post(
        "/api/files",
        data={"file": (io.BytesIO(b"x"), "a.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert client.s3.list_objects_v2(Bucket=BUCKET).get("KeyCount") == 0


def test_wrong_csrf_token_rejected(client):
    csrf_token(client)
    response = upload(client, "0" * 64, b"x", "a.txt")
    assert response.status_code == 400


def test_delete_without_csrf_token_rejected(client):
    token = csrf_token(client)
    upload(client, token, b"keep", "keep.txt")
    assert client.delete("/api/files/keep.txt").status_code == 400
    head = client.s3.head_object(Bucket=BUCKET, Key="vault/keep.txt")
    assert head["ContentLength"] == 4


def test_filename_is_sanitised(client):
    token = csrf_token(client)
    upload(client, token, b"x", "../../etc/passwd")
    keys = [o["Key"] for o in client.s3.list_objects_v2(Bucket=BUCKET).get("Contents", [])]
    assert keys == ["vault/etc_passwd"]


def test_path_traversal_download_blocked(client):
    assert client.get("/files/..%2F..%2Fsecret").status_code == 404


def test_delete_keeps_previous_version(client):
    token = csrf_token(client)
    upload(client, token, b"v1", "notes.txt")
    response = client.delete("/api/files/notes.txt", headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    assert response.get_json()["deleted"] is True
    versions = client.s3.list_object_versions(Bucket=BUCKET, Prefix="vault/notes.txt")
    assert len(versions.get("Versions", [])) == 1
    assert len(versions.get("DeleteMarkers", [])) == 1


def test_security_posture_endpoint(client):
    client.s3.put_public_access_block(
        Bucket=BUCKET,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    client.s3.put_bucket_encryption(
        Bucket=BUCKET,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]
        },
    )
    posture = client.get("/api/security").get_json()
    assert posture["default_encryption"]["algorithm"] == "aws:kms"
    assert posture["all_public_access_blocked"] is True
    assert posture["versioning"] == "Enabled"


def test_session_bootstrap_has_no_instance_identity_off_ec2(client):
    data = client.get("/api/session").get_json()
    assert data["instance"] == {}
    assert data["max_upload_bytes"] == 10 * 1024 * 1024


def test_session_reports_client_ip_from_nginx_header(client):
    data = client.get("/api/session", headers={"X-Forwarded-For": "10.100.0.6"}).get_json()
    assert data["client_ip"] == "10.100.0.6"


UI_ORIGIN = "https://vault-ui.example.app"


@pytest.fixture
def cors_client():
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)
        app = create_app(
            s3_client=s3,
            config={"BUCKET": BUCKET, "TESTING": True, "ALLOWED_ORIGINS": UI_ORIGIN},
        )
        assert app.config["SESSION_COOKIE_SAMESITE"] == "None"
        with app.test_client() as test_client:
            yield test_client


def test_cors_off_by_default(client):
    response = client.get("/api/session", headers={"Origin": UI_ORIGIN})
    assert "Access-Control-Allow-Origin" not in response.headers
    preflight = client.options("/api/files", headers={"Origin": UI_ORIGIN, "Access-Control-Request-Method": "POST"})
    assert preflight.status_code == 403


def test_cors_preflight_allows_listed_origin_only(cors_client):
    ok = cors_client.options(
        "/api/files",
        headers={
            "Origin": UI_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Private-Network": "true",
        },
    )
    assert ok.status_code == 204
    assert "X-CSRF-Token" in ok.headers["Access-Control-Allow-Headers"]
    assert ok.headers["Access-Control-Allow-Private-Network"] == "true"

    bad = cors_client.options(
        "/api/files", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"}
    )
    assert bad.status_code == 403


def test_cors_response_headers_and_csrf_still_enforced(cors_client):
    response = cors_client.get("/api/session", headers={"Origin": UI_ORIGIN})
    assert response.headers["Access-Control-Allow-Origin"] == UI_ORIGIN
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert "SameSite=None" in response.headers["Set-Cookie"]

    other = cors_client.get("/api/session", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in other.headers

    no_token = cors_client.delete("/api/files/x.txt", headers={"Origin": UI_ORIGIN})
    assert no_token.status_code == 400
