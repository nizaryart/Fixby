from fastapi import APIRouter, Depends, FastAPI

app = FastAPI()


def require_token(): ...


# ok: api-router-without-token-check
api = APIRouter(prefix="/api", dependencies=[Depends(require_token)])

# ruleid: api-router-without-token-check
admin = APIRouter(prefix="/api/admin")

# ruleid: api-router-without-token-check
legacy = APIRouter(prefix="/api", tags=["legacy"])

# ok: api-router-without-token-check
public = APIRouter(prefix="/public")


# ok: api-route-outside-protected-router
@app.get("/health")
def health(): ...


# ruleid: api-route-outside-protected-router
@app.delete("/api/findings/{finding_id}")
def delete_finding(finding_id: int): ...


# ok: api-route-outside-protected-router
@api.get("/findings")
def list_findings(): ...


# ruleid: api-route-outside-protected-router
app.add_api_route("/api/export", list_findings)
