from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from ..models import Evidence, ExecutionResult, Experiment
from .base import ExperimentExecutor


class HttpAuthorizationExecutor(ExperimentExecutor):
    """
    Execute one explicitly specified HTTP authorization experiment.

    The executor records HTTP facts only. It does not decide whether
    the response represents a vulnerability or authorization failure.
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
            id=f"http:{experiment.id}",
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
