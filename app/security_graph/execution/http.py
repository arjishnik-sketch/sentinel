from uuid import uuid4
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from ..models import Evidence, ExecutionResult, Experiment
from .base import ExperimentExecutor


class HttpAuthorizationExecutor(ExperimentExecutor):
    """
    Execute one explicitly specified HTTP authorization experiment.

    The executor records HTTP facts only. It does not decide whether
    the response represents a vulnerability or authorization failure.

    An optional host allowlist bounds every request to the engagement
    scope. When configured, requests to any other host are refused
    before a connection is opened. This makes live probing safe by
    construction: Sentinel only ever contacts the target it was told
    to investigate.
    """

    kind = "authorization_http_check"

    _ALLOWED_METHODS = frozenset({
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    })

    _ALLOWED_SCHEMES = frozenset({"http", "https"})

    def __init__(self, allowed_hosts: set[str] | None = None) -> None:
        # When None, no scope restriction is applied (preserves the
        # unbounded behaviour used by dry-run and unit tests). When a
        # set is supplied, only those netlocs may be contacted.
        self.allowed_hosts = (
            {host.lower() for host in allowed_hosts}
            if allowed_hosts is not None
            else None
        )

    def _enforce_scope(self, url: str) -> None:
        parsed = urlparse(url)

        scheme = (parsed.scheme or "").lower()

        if scheme not in self._ALLOWED_SCHEMES:
            raise ValueError(
                f"Refusing non-HTTP scheme for authorization probe: "
                f"{scheme or 'none'}"
            )

        if self.allowed_hosts is None:
            return

        host = (parsed.netloc or "").lower()

        if host not in self.allowed_hosts:
            raise ValueError(
                f"Refusing out-of-scope host: {host or 'none'}. "
                f"In-scope hosts: {sorted(self.allowed_hosts)}"
            )

    def execute(self, experiment: Experiment) -> ExecutionResult:
        if experiment.kind != self.kind:
            raise ValueError(
                f"Unsupported experiment kind: {experiment.kind}"
            )

        request_spec = experiment.request

        if request_spec is None:
            raise ValueError(
                "HTTP authorization experiment requires a request specification."
            )

        method = request_spec.method.strip().upper()

        if method not in self._ALLOWED_METHODS:
            raise ValueError(
                f"Unsupported HTTP method: {method}"
            )

        if not request_spec.url.strip():
            raise ValueError("HTTP request URL cannot be empty.")

        if request_spec.timeout <= 0:
            raise ValueError("HTTP request timeout must be positive.")

        # Bound the request to the engagement scope before any network
        # activity occurs.
        self._enforce_scope(request_spec.url)

        headers = dict(request_spec.headers)

        body = (
            request_spec.body.encode("utf-8")
            if request_spec.body is not None
            else None
        )

        request = Request(
            request_spec.url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with urlopen(
                request,
                timeout=request_spec.timeout,
            ) as response:
                status_code = response.status
                response_body = response.read()
                response_headers = dict(response.headers.items())

        except HTTPError as exc:
            status_code = exc.code
            response_headers = dict(exc.headers.items())
            response_body = exc.read()

        except URLError as exc:
            raise RuntimeError(
                f"HTTP request failed: {exc.reason}"
            ) from exc

        evidence_data = {
            "executor": self.kind,
            "mode": "http",
            "experiment_id": experiment.id,
            "method": method,
            "url": request_spec.url,
            "status_code": status_code,
            "response_headers": response_headers,
            "response_body_length": len(response_body),
            "expected_statuses": request_spec.expected_statuses,
            "expected_outcome": request_spec.expected_outcome,
        }

        if request_spec.principal_id is not None:
            evidence_data["principal_id"] = request_spec.principal_id

        if request_spec.resource_id is not None:
            evidence_data["resource_id"] = request_spec.resource_id

        if request_spec.action is not None:
            evidence_data["action"] = request_spec.action

        evidence = Evidence(
            id=f"http:{experiment.id}:{uuid4().hex}",
            source="http_response",
            data=evidence_data,
            confidence=1.0,
        )

        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(
                ("mode", "http"),
                ("executor", self.kind),
                ("status_code", str(status_code)),
            ),
        )
