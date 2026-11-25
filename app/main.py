import os
import secrets
import sqlite3
from datetime import date, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from app import store
from app.cvss import CVSSError, base_score, severity
from app.policy import SLA_DAYS, TRANSITIONS

Status = Literal["reported", "triaged", "patched", "disclosed", "rejected"]


class FindingIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    product: str = Field(min_length=1, max_length=200)
    cvss_vector: str = Field(max_length=64)
    reported_on: date | None = None
    cve: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")


class StatusChange(BaseModel):
    status: Status


def require_token(authorization: str = Header(default="")) -> None:
    expected = os.getenv("VULNTRACK_TOKEN", "")
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "API token is not configured")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token", headers={"WWW-Authenticate": "Bearer"})


app = FastAPI(title="VulnTrack", version=os.getenv("VULNTRACK_VERSION", "dev"), openapi_url=None)
api = APIRouter(prefix="/api", dependencies=[Depends(require_token)])


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict:
    try:
        store.ping()
    except sqlite3.Error as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable") from exc
    return {"status": "ready"}


@api.get("/findings")
def list_findings(state: Status | None = Query(default=None, alias="status"), overdue: bool = False) -> list[dict]:
    return store.list_findings(status=state, overdue_on=date.today() if overdue else None)


@api.post("/findings", status_code=status.HTTP_201_CREATED)
def create_finding(body: FindingIn) -> dict:
    try:
        score = base_score(body.cvss_vector)
    except CVSSError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    level = severity(score)
    reported_on = body.reported_on or date.today()
    return store.create(
        {
            "title": body.title,
            "product": body.product,
            "cvss_vector": body.cvss_vector,
            "score": score,
            "severity": level,
            "cve": body.cve,
            "reported_on": reported_on.isoformat(),
            "due_on": (reported_on + timedelta(days=SLA_DAYS[level])).isoformat(),
        }
    )


@api.get("/findings/{finding_id}")
def get_finding(finding_id: int) -> dict:
    finding = store.get(finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return finding


@api.patch("/findings/{finding_id}")
def change_status(finding_id: int, body: StatusChange) -> dict:
    finding = get_finding(finding_id)
    if body.status not in TRANSITIONS[finding["status"]]:
        raise HTTPException(status.HTTP_409_CONFLICT, f"cannot move from {finding['status']} to {body.status}")
    return store.set_status(finding_id, body.status)


app.include_router(api)
