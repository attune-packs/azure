import unittest

from actions.lib.runtime import Runtime, collect_pages
from actions.lib.security import AzurePackError

PROFILE = {"cloud": "public", "auth_mode": "managed_identity"}
UUID1 = "11111111-1111-1111-1111-111111111111"


class Token:
    token = "test-token"


class Credential:
    def __init__(self):
        self.scopes = []

    def get_token(self, scope):
        self.scopes.append(scope)
        return Token()


class Response:
    def __init__(self, status, payload=None, headers=None):
        self.status_code = status
        self._payload = payload
        self.headers = headers or {}
        self.content = b"" if payload is None else b"json"

    def json(self):
        return self._payload


class Session:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


class Poller:
    def __init__(self, status="Succeeded", result=None):
        self._status = status
        self._result = result
        self.timeout = None

    def result(self, timeout):
        self.timeout = timeout
        return self._result

    def status(self):
        return self._status


class RuntimeTests(unittest.TestCase):
    def runtime(self, session=None, sleeper=lambda _: None):
        runtime = Runtime(PROFILE, session=session, sleeper=sleeper)
        runtime._credential_instance = Credential()
        return runtime

    def test_graph_read_retries_are_bounded_and_tls_is_enforced(self):
        sleeps = []
        session = Session(
            [
                Response(429, {"error": {"code": "throttle"}}, {"Retry-After": "999"}),
                Response(200, {"value": []}),
            ]
        )
        runtime = self.runtime(session, sleeps.append)
        result = runtime.op_graph_users_list()
        self.assertEqual(result["count"], 0)
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(sleeps, [30.0])
        self.assertTrue(all(call[2]["verify"] is True for call in session.calls))
        self.assertTrue(
            all(call[2]["allow_redirects"] is False for call in session.calls)
        )
        self.assertEqual(
            runtime.credential.scopes, ["https://graph.microsoft.com/.default"]
        )

    def test_graph_write_is_not_retried(self):
        session = Session(
            [Response(503, {"error": {"code": "Unavailable", "message": "retry"}})]
        )
        runtime = self.runtime(session)
        with self.assertRaisesRegex(AzurePackError, "Unavailable"):
            runtime._graph_request("POST", "groups", body={"displayName": "x"})
        self.assertEqual(len(session.calls), 1)

    def test_graph_pagination_rejects_malicious_next_link(self):
        session = Session(
            [
                Response(
                    200,
                    {
                        "value": [{"id": UUID1}],
                        "@odata.nextLink": "https://attacker.invalid/v1.0/users?$skiptoken=x",
                    },
                )
            ]
        )
        runtime = self.runtime(session)
        with self.assertRaisesRegex(AzurePackError, "allowlist"):
            runtime.op_graph_users_list()

    def test_role_assignable_group_mutation_is_blocked(self):
        session = Session([Response(200, {"id": UUID1, "isAssignableToRole": True})])
        runtime = self.runtime(session)
        with self.assertRaisesRegex(AzurePackError, "role-assignable"):
            runtime._assert_group_not_role_assignable(UUID1)

    def test_lro_must_finish_successfully_and_timeout_is_forwarded(self):
        runtime = self.runtime()
        poller = Poller(result={"id": "resource"})
        result = runtime._finish("test", poller, 123)
        self.assertEqual(result["status"], "Succeeded")
        self.assertEqual(poller.timeout, 123)
        with self.assertRaisesRegex(AzurePackError, "did not succeed"):
            runtime._finish("test", Poller(status="Failed"), 123)
        with self.assertRaises(AzurePackError):
            runtime._finish("test", Poller(), 9999)

    def test_pagination_limits_are_deterministic(self):
        items, truncated = collect_pages(range(10), 3, 2)
        self.assertEqual(items, [0, 1, 2])
        self.assertTrue(truncated)


if __name__ == "__main__":
    unittest.main()
