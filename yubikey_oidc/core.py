from __future__ import annotations

import json
import shlex
import subprocess
from base64 import urlsafe_b64encode
from configparser import ConfigParser
from datetime import UTC, datetime, timedelta
from functools import cached_property
from hashlib import sha256
from pathlib import Path
from shutil import which
from typing import Any, TypedDict
from urllib.parse import urljoin, urlparse
from uuid import UUID

import boto3
from jwt.algorithms import RSAAlgorithm

YUBICO_PIV_TOOL = which("yubico-piv-tool")

if not YUBICO_PIV_TOOL:
    raise RuntimeError("yubico-piv-tool not found in PATH")

YKMAN = which("ykman")

if not YKMAN:
    raise RuntimeError("ykman not found in PATH")


class AwsCredentials(TypedDict):
    AccessKeyId: str
    SecretAccessKey: str
    SessionToken: str
    Expiration: datetime


class YubikeyOIDC:
    aud = "sts.amazonaws.com"

    def __init__(self, iss: str, sub: str, slot: str) -> None:
        self.iss = iss
        self.sub = sub
        self.slot = slot

    @property
    def kid(self) -> str:
        return str(UUID(bytes=sha256(self.public_key.encode()).digest()[:16]))

    @cached_property
    def public_key(self) -> str:
        p = subprocess.run(
            args=shlex.split(f"{YKMAN} piv keys export {self.slot} -"),
            capture_output=True,
        )

        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode())

        # noinspection PyTypeChecker
        return p.stdout.decode()

    @property
    def jwks(self) -> dict:
        rsa = RSAAlgorithm(RSAAlgorithm.SHA256)
        key = rsa.to_jwk(rsa.prepare_key(self.public_key), as_dict=True)
        return {
            "keys": [
                {
                    "alg": "RS256",
                    "kid": self.kid,
                    "kty": "RSA",
                    "n": key["n"],
                    "e": key["e"],
                    "use": "sig",
                }
            ]
        }

    @property
    def openid_configuration(self) -> dict:
        return {
            "issuer": self.iss,
            "jwks_uri": urljoin(self.iss, "/.well-known/jwks.json"),
            "id_token_signing_alg_values_supported": ["RS256"],
            "subject_types_supported": ["public"],
            "response_types_supported": ["id_token"],
        }

    def generate_public_key(self) -> str:
        p = subprocess.run(
            args=shlex.split(
                f"{YUBICO_PIV_TOOL} "
                f"-a generate "
                f"-s {self.slot} "
                f"-A RSA2048 "
                f"-H SHA256 "
                f"--pin-policy=never "
                f"--touch-policy=always"
            ),
            capture_output=True,
        )

        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode())

        # noinspection PyTypeChecker
        return p.stdout.decode()

    def create_token(self, exp: timedelta) -> str:
        iat = datetime.now(UTC)
        iat_timestamp = int(iat.timestamp())

        payload_segment = base64url_encode_json(
            {
                "iss": self.iss,
                "sub": self.sub,
                "aud": self.aud,
                "iat": iat_timestamp,
                "exp": int((iat + exp).timestamp()),
                "nbf": iat_timestamp,
            }
        )

        headers_segment = base64url_encode_json(
            {
                "kid": self.kid,
                "typ": "JWT",
                "alg": "RS256",
            }
        )

        message = headers_segment + b"." + payload_segment
        signature = sign_with_yubikey(message, self.slot)
        signature_segment = base64url_encode(signature)
        token = message + b"." + signature_segment

        return token.decode("utf-8")

    def deploy_openid(self, s3_bucket: str) -> None:
        s3 = boto3.client("s3")
        s3.put_object(
            Bucket=s3_bucket,
            Key=".well-known/jwks.json",
            Body=json.dumps(self.jwks),
            ContentType="application/json",
            CacheControl="no-cache, no-store, must-revalidate",
        )
        s3.put_object(
            Bucket=s3_bucket,
            Key=".well-known/openid-configuration",
            Body=json.dumps(self.openid_configuration),
            ContentType="application/json",
            CacheControl="no-cache, no-store, must-revalidate",
        )

    def create_trust_policy(self, account: str) -> dict:
        provider = urlparse(self.iss).hostname
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": f"arn:aws:iam::{account}:oidc-provider/{provider}"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{provider}:sub": self.sub,
                            f"{provider}:aud": self.aud,
                        }
                    },
                }
            ],
        }

    def assume_role(self, rolearn: str, exp: timedelta) -> AwsCredentials:
        iss_sub_hash = sha256(f"{self.iss}-{self.sub}".encode()).hexdigest()
        session_name = f"yubikey-{iss_sub_hash}"[:64]
        response = boto3.client("sts").assume_role_with_web_identity(
            RoleArn=rolearn,
            RoleSessionName=session_name,
            WebIdentityToken=self.create_token(exp=exp),
        )
        return response["Credentials"]

    def login_to_aws(self, profilename: str, rolearn: str, exp: timedelta) -> None:
        credentials = self.assume_role(rolearn, exp)
        config = ConfigParser()
        credentials_path = Path.home() / ".aws" / "credentials"
        config.read(credentials_path)
        if profilename not in config:
            config.add_section(profilename)
        config[profilename]["aws_access_key_id"] = credentials["AccessKeyId"]
        config[profilename]["aws_secret_access_key"] = credentials["SecretAccessKey"]
        config[profilename]["aws_session_token"] = credentials["SessionToken"]
        config[profilename]["aws_session_expiration"] = credentials[
            "Expiration"
        ].isoformat()
        with open(credentials_path, "wt") as f:
            config.write(f)


def base64url_encode_json(data: Any) -> bytes:
    return base64url_encode(
        json.dumps(
            data,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def base64url_encode(data: bytes) -> bytes:
    return urlsafe_b64encode(data).replace(b"=", b"")


def sign_with_yubikey(msg: bytes, slot: str, pin: str = "123456") -> bytes:
    completed = subprocess.run(
        args=shlex.split(
            f"{YUBICO_PIV_TOOL} -a verify-pin --sign -s {slot} -A RSA2048 -H SHA256 -P {pin} -i - -o -"
        ),
        input=msg,
        capture_output=True,
    )

    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode())

    # noinspection PyTypeChecker
    return completed.stdout
