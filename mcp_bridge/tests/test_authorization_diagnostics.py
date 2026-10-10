"""Diagnostic metadata contains fixed codes only, never request/secret values."""
import json
import socket
import unittest
from unittest.mock import MagicMock, patch

from mcp_bridge import cimd
from mcp_bridge.server import authorization_diagnostic
from mcp_bridge.tests.test_security import DOC, SecurityTests


class DiagnosticTests(SecurityTests):
    def test_parameter_rejection_is_distinct_from_owner_or_csrf(self):
        response=self.client.get('/oauth/authorize',params=self.authdata(resource='https://attacker.invalid/mcp'))
        self.assertEqual(response.status_code,400)
        self.assertEqual(response.json(),{'error':'authorization_rejected','stage':'parameters','reason':'invalid_resource'})
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM records WHERE kind='code'").fetchone()[0],0)

    def test_client_metadata_rejection_is_fixed_code_only(self):
        with patch.object(self.oauth.cimd,'prepare',side_effect=ValueError('cimd_http_rejected')):
            response=self.client.get('/oauth/authorize',params=self.authdata())
        self.assertEqual(response.json(),{'error':'authorization_rejected','stage':'client_metadata','reason':'cimd_http_rejected'})

    def test_unknown_exception_never_exposes_request_cookie_token_or_body(self):
        secret='SYNTHETIC_SECRET_COOKIE_PKCE_STATE_TOKEN'
        with patch.object(self.oauth.cimd,'prepare',side_effect=ValueError(secret)):
            response=self.client.get('/oauth/authorize',params=self.authdata(state=secret))
        self.assertNotIn(secret,response.text)
        self.assertEqual(response.json()['reason'],'validation_failed')
        for error in (RuntimeError(secret),ValueError({'secret':secret}),TypeError(secret),OSError(secret)):
            self.assertNotIn(secret,json.dumps(authorization_diagnostic('client_metadata',error)))

    def test_session_and_pending_capacity_failures_are_distinct_without_token_creation(self):
        original=self.store.put
        for kind,stage in (('session','browser_session'),('pending','pending_storage')):
            self.client.cookies.clear()
            def fail(record_kind,*args,**kwargs):
                if record_kind==kind:raise ValueError('capacity_reached')
                return original(record_kind,*args,**kwargs)
            with patch.object(self.store,'put',side_effect=fail):
                response=self.client.get('/oauth/authorize',params=self.authdata())
            self.assertEqual(response.json(),{'error':'authorization_rejected','stage':stage,'reason':'capacity_reached'})
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM records WHERE kind IN ('token','refresh_family','code')").fetchone()[0],0)


class ResolverFuture:
    def __init__(self,minimum_seconds=None):
        self.minimum_seconds=minimum_seconds;self.callbacks=[];self.timeouts=[];self.cancel_calls=0

    def add_done_callback(self,callback):self.callbacks.append(callback)

    def result(self,timeout):
        self.timeouts.append(timeout)
        if self.minimum_seconds is None or timeout<self.minimum_seconds:raise TimeoutError()
        for callback in self.callbacks:callback(self)
        return [(socket.AF_INET,1,6,'',('93.184.216.34',443))]

    def cancel(self):
        self.cancel_calls+=1
        return False  # Models an already running OS resolver, not cancellable.


class DNSBudgetTests(unittest.TestCase):
    def test_four_second_cold_resolver_succeeds_within_existing_total_deadline(self):
        loader=cimd.CIMD();future=ResolverFuture(4);connection=MagicMock()
        response=MagicMock();response.status=200
        response.getheader.side_effect=lambda key,default=None: {'Content-Type':'application/json'}.get(key,default)
        response.read.return_value=json.dumps(DOC).encode();connection.getresponse.return_value=response
        try:
            with patch.object(loader.dns,'submit',return_value=future),patch('mcp_bridge.cimd.socket.socket'),patch('mcp_bridge.cimd.ssl.create_default_context') as tls,patch('mcp_bridge.cimd.http.client.HTTPSConnection',return_value=connection),patch('mcp_bridge.cimd.threading.Timer') as timer:
                value=loader.prepare(cimd.STABLE)
            self.assertEqual(value['grant_types'],['authorization_code','refresh_token'])
            self.assertGreaterEqual(future.timeouts[0],4);self.assertLessEqual(future.timeouts[0],5)
            self.assertLessEqual(timer.call_args.args[0],10)
            self.assertEqual(tls.return_value.wrap_socket.call_args.kwargs['server_hostname'],'chatgpt.com')
        finally:loader.close()

    def test_slow_resolvers_fail_closed_with_fixed_reason_and_two_job_limit(self):
        loader=cimd.CIMD();jobs=[]
        def submit(*args):
            future=ResolverFuture();jobs.append(future);return future
        try:
            with patch.object(loader.dns,'submit',side_effect=submit),patch('mcp_bridge.cimd.http.client.HTTPSConnection') as https:
                for _ in range(2):
                    with self.assertRaisesRegex(ValueError,'^cimd_dns_timeout$'):loader.prepare(cimd.STABLE)
                with self.assertRaisesRegex(ValueError,'^cimd_dns_busy$'):loader.prepare(cimd.STABLE)
            self.assertEqual(len(jobs),2);self.assertTrue(all(future.cancel_calls==1 for future in jobs))
            https.assert_not_called();self.assertIsNone(loader.cached(cimd.STABLE))
            self.assertEqual(authorization_diagnostic('client_metadata',ValueError('cimd_dns_timeout')),{'stage':'client_metadata','reason':'cimd_dns_timeout'})
        finally:loader.close()


def load_tests(loader,tests,pattern):
    suite=unittest.TestSuite(DiagnosticTests(name) for name in DiagnosticTests.__dict__ if name.startswith('test_'))
    suite.addTests(loader.loadTestsFromTestCase(DNSBudgetTests))
    return suite
