"""Secure Vault: internal document service reachable only over the VPN.

Files are stored in S3 with SSE-KMS (customer-managed key). The S3 bucket
policy only allows object access through the VPC endpoint, so this service
is the only way users can read or write files.

Python 3.9 compatible (Amazon Linux 2023 system Python).
"""

import hmac
import json
import logging
import os
import secrets
import socket
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    request,
    session,
    stream_with_context,
)
from werkzeug.utils import secure_filename

PREFIX = "vault/"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
STARTED_AT = time.time()


class JsonFormatter(logging.Formatter):
    """One JSON object per line so CloudWatch metric filters can match fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(getattr(record, "extra_fields", {}))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(log_file: Optional[str]) -> logging.Logger:
    logger = logging.getLogger("vault")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    handler: logging.Handler = logging.FileHandler(log_file) if log_file else logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def audit(logger: logging.Logger, event: str, **fields: Any) -> None:
    fields.update(
        {
            "event": event,
            "client_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "request_id": getattr(g, "request_id", None),
        }
    )
    logger.info(event, extra={"extra_fields": fields})


def instance_identity() -> Dict[str, str]:
    """Read instance identity via IMDSv2 (token required). Empty off-EC2."""
    try:
        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        token = urllib.request.urlopen(token_req, timeout=1).read().decode()
        doc_req = urllib.request.Request(
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            headers={"X-aws-ec2-metadata-token": token},
        )
        doc = json.loads(urllib.request.urlopen(doc_req, timeout=1).read().decode())
        public_ip_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            headers={"X-aws-ec2-metadata-token": token},
        )
        try:
            public_ip = urllib.request.urlopen(public_ip_req, timeout=1).read().decode()
        except Exception:  # 404 when the instance has no public IP
            public_ip = "none"
        return {
            "instance_id": doc.get("instanceId", ""),
            "instance_type": doc.get("instanceType", ""),
            "availability_zone": doc.get("availabilityZone", ""),
            "private_ip": doc.get("privateIp", ""),
            "public_ip": public_ip,
            "imds": "v2 (token required)",
        }
    except Exception:
        return {}


def create_app(s3_client: Any = None, config: Optional[Dict[str, Any]] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        BUCKET=os.environ.get("VAULT_BUCKET", ""),
        KMS_KEY_ARN=os.environ.get("VAULT_KMS_KEY_ARN", ""),
        ENVIRONMENT=os.environ.get("VAULT_ENVIRONMENT", "dev"),
        PROJECT=os.environ.get("VAULT_PROJECT", "securevpn"),
        FQDN=os.environ.get("VAULT_FQDN", "localhost"),
        SECRET_KEY=os.environ.get("VAULT_SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # Comma-separated origins (e.g. a hosted copy of the UI) allowed to call
        # the API cross-origin. Empty (the default) keeps the API same-origin only.
        ALLOWED_ORIGINS=os.environ.get("VAULT_ALLOWED_ORIGINS", ""),
    )
    if config:
        app.config.update(config)

    allowed_origins = {o.strip().rstrip("/") for o in app.config["ALLOWED_ORIGINS"].split(",") if o.strip()}
    if allowed_origins:
        # The session cookie must travel on cross-site requests from the allowed
        # origins. CSRF stays enforced: the X-CSRF-Token header forces a CORS
        # preflight, and only the allowlisted origins pass it.
        app.config["SESSION_COOKIE_SAMESITE"] = "None"

    logger = configure_logging(os.environ.get("VAULT_LOG_FILE"))
    s3 = s3_client or boto3.client("s3")
    identity_cache: Dict[str, Any] = {}

    def identity() -> Dict[str, str]:
        if "value" not in identity_cache:
            identity_cache["value"] = instance_identity()
        return identity_cache["value"]

    # -- request lifecycle ----------------------------------------------------

    def cors_origin() -> Optional[str]:
        origin = request.headers.get("Origin", "")
        return origin if origin in allowed_origins else None

    @app.before_request
    def start_request() -> Optional[Response]:
        g.request_id = request.headers.get("X-Request-Id") or secrets.token_hex(8)
        g.started = time.monotonic()
        if request.method == "OPTIONS" and request.headers.get("Access-Control-Request-Method"):
            # CORS preflight: answered here so it never reaches CSRF checks or routes.
            if not cors_origin():
                abort(403, description="Origin not allowed")
            preflight = Response(status=204)
            preflight.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE"
            preflight.headers["Access-Control-Allow-Headers"] = "X-CSRF-Token, Content-Type"
            preflight.headers["Access-Control-Max-Age"] = "600"
            # Chrome asks before a public site may call a private (VPN) address.
            if request.headers.get("Access-Control-Request-Private-Network") == "true":
                preflight.headers["Access-Control-Allow-Private-Network"] = "true"
            return preflight
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent, expected):
                audit(logger, "csrf_rejected", path=request.path)
                abort(400, description="Invalid or missing CSRF token")

    @app.after_request
    def add_headers(response: Response) -> Response:
        response.headers["X-Request-Id"] = g.get("request_id", "")
        response.headers.setdefault("Cache-Control", "no-store")
        origin = cors_origin() if allowed_origins else None
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Expose-Headers"] = "X-Request-Id"
        if allowed_origins:
            response.headers.add("Vary", "Origin")
        return response

    def csrf_token() -> str:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def json_error(exc: Any):
        code = getattr(exc, "code", 500)
        messages = {
            400: getattr(exc, "description", "Bad request"),
            403: getattr(exc, "description", "Forbidden"),
            404: "Not found",
            413: f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)",
        }
        return jsonify({"error": messages.get(code, "Error")}), code

    # -- helpers --------------------------------------------------------------

    def list_files() -> List[Dict[str, Any]]:
        files: List[Dict[str, Any]] = []
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=app.config["BUCKET"], Prefix=PREFIX):
            for obj in page.get("Contents", []):
                name = obj["Key"][len(PREFIX):]
                if name:
                    files.append(
                        {
                            "name": name,
                            "size": obj["Size"],
                            "modified": obj["LastModified"].strftime("%Y-%m-%d %H:%M UTC"),
                        }
                    )
        return sorted(files, key=lambda f: f["name"].lower())

    def object_key(name: str) -> str:
        clean = secure_filename(name)
        if not clean or clean != name:
            abort(404)
        return PREFIX + clean

    # -- routes -----------------------------------------------------------------

    @app.get("/api/session")
    def api_session():
        """Bootstrap data for the browser UI: CSRF token and server context."""
        return jsonify(
            {
                "csrf_token": csrf_token(),
                "project": app.config["PROJECT"],
                "environment": app.config["ENVIRONMENT"],
                "fqdn": app.config["FQDN"],
                "hostname": socket.gethostname(),
                "client_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                "instance": identity(),
                "kms_key_configured": bool(app.config["KMS_KEY_ARN"]),
                "max_upload_bytes": MAX_UPLOAD_BYTES,
            }
        )

    @app.get("/api/files")
    def api_list_files():
        try:
            return jsonify({"files": list_files()})
        except (ClientError, BotoCoreError):
            logger.exception("list_failed", extra={"extra_fields": {"event": "list_failed"}})
            return jsonify({"error": "Could not list files from encrypted storage"}), 502

    @app.post("/api/files")
    def api_upload():
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            return jsonify({"error": "Choose a file to upload"}), 400

        name = secure_filename(uploaded.filename)
        if not name:
            return jsonify({"error": "Invalid file name"}), 400

        extra: Dict[str, str] = {"ServerSideEncryption": "aws:kms"}
        if app.config["KMS_KEY_ARN"]:
            extra["SSEKMSKeyId"] = app.config["KMS_KEY_ARN"]
        try:
            s3.upload_fileobj(uploaded.stream, app.config["BUCKET"], PREFIX + name, ExtraArgs=extra)
        except (ClientError, BotoCoreError):
            logger.exception("upload_failed", extra={"extra_fields": {"event": "upload_failed", "file": name}})
            return jsonify({"error": "Upload failed"}), 502

        audit(logger, "file_uploaded", file=name)
        return jsonify({"file": name, "server_side_encryption": "aws:kms"}), 201

    @app.delete("/api/files/<name>")
    def api_delete(name: str):
        key = object_key(name)
        s3.delete_object(Bucket=app.config["BUCKET"], Key=key)
        audit(logger, "file_deleted", file=name)
        return jsonify({"file": name, "deleted": True, "previous_versions_retained_days": 30})

    @app.get("/files/<name>")
    def download(name: str):
        key = object_key(name)
        try:
            obj = s3.get_object(Bucket=app.config["BUCKET"], Key=key)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                abort(404)
            raise
        audit(logger, "file_downloaded", file=name)
        body = obj["Body"]
        return Response(
            stream_with_context(body.iter_chunks(chunk_size=64 * 1024)),
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{name}"',
                "Content-Length": str(obj.get("ContentLength", "")),
            },
        )

    @app.get("/files/<name>/info")
    def file_info(name: str):
        key = object_key(name)
        try:
            head = s3.head_object(Bucket=app.config["BUCKET"], Key=key)
        except ClientError:
            abort(404)
        return jsonify(
            {
                "file": name,
                "size": head.get("ContentLength"),
                "server_side_encryption": head.get("ServerSideEncryption"),
                "kms_key_id": head.get("SSEKMSKeyId"),
                "bucket_key_enabled": head.get("BucketKeyEnabled", False),
                "version_id": head.get("VersionId"),
                "last_modified": head["LastModified"].isoformat() if head.get("LastModified") else None,
            }
        )

    @app.get("/health")
    def health():
        checks = {"app": "ok"}
        status = 200
        try:
            s3.list_objects_v2(Bucket=app.config["BUCKET"], Prefix=PREFIX, MaxKeys=1)
            checks["storage"] = "ok"
        except (ClientError, BotoCoreError) as exc:
            checks["storage"] = f"error: {type(exc).__name__}"
            status = 503
        return (
            jsonify(
                {
                    "status": "ok" if status == 200 else "degraded",
                    "checks": checks,
                    "uptime_seconds": int(time.time() - STARTED_AT),
                    "environment": app.config["ENVIRONMENT"],
                }
            ),
            status,
        )

    @app.get("/api/security")
    def security_posture():
        bucket = app.config["BUCKET"]
        posture: Dict[str, Any] = {"bucket": bucket, "instance": identity()}
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"][0]
            posture["default_encryption"] = {
                "algorithm": enc["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"],
                "kms_key": enc["ApplyServerSideEncryptionByDefault"].get("KMSMasterKeyID"),
                "bucket_key_enabled": enc.get("BucketKeyEnabled", False),
            }
            pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            posture["public_access_block"] = pab
            posture["all_public_access_blocked"] = all(pab.values())
            posture["versioning"] = s3.get_bucket_versioning(Bucket=bucket).get("Status", "Disabled")
        except (ClientError, BotoCoreError) as exc:
            posture["error"] = type(exc).__name__
        posture["transport"] = {
            "scheme": request.headers.get("X-Forwarded-Proto", request.scheme),
            "tls_protocol": request.headers.get("X-TLS-Protocol"),
            "tls_cipher": request.headers.get("X-TLS-Cipher"),
        }
        return jsonify(posture)

    return app
