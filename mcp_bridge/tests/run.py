"""Safe aggregate results: no credentials, tokens, challenges or response bodies."""
import io
import json
import logging
import resource
import threading
import unittest


def main():
    threading.stack_size(524288)
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))
    logging.disable(logging.CRITICAL)
    suite=unittest.defaultTestLoader.discover('/app/mcp_bridge/tests',pattern='test_*.py')
    runner=unittest.TextTestRunner(stream=io.StringIO(),verbosity=0)
    result=runner.run(suite)
    report={"tests":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),
            "failed_tests":[test.id() for test,_ in result.failures+result.errors],
            "peak_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,"address_space_limit_mib":256,
            "synthetic_credentials_only":True,"production_identity_mounted":False,"provider_credentials_mounted":False,
            "maximum_inflight_http":4,"public_client_fixture_only":True}
    print(json.dumps(report),flush=True)
    if not result.wasSuccessful():
        # Tracebacks are deliberately kept out of tool output; identify only
        # source line + exception class to debug without dumping raw bodies.
        import re
        for test,trace in result.failures+result.errors:
            locations=re.findall(r'File "([^"]+)", line (\d+)',trace)
            final=trace.strip().splitlines()[-1].split(':',1)[0]
            print(json.dumps({"test":test.id(),"locations":locations,"exception":final[:100]}))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__=='__main__':main()
