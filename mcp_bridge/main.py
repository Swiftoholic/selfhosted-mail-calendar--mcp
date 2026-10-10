"""Fixed deployment entry point. No configurable synthetic mode or login bypass."""
import logging
import os
import resource
import threading

import uvicorn

from .config import IDENTITY_FILE
from .server import create_app
from .store import Store


def main():
    if os.environ.get("AUTHLIB_INSECURE_TRANSPORT"):
        raise SystemExit("Insecure OAuth mode is forbidden")
    threading.stack_size(524288)
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    logging.disable(logging.CRITICAL)
    store = Store(IDENTITY_FILE)
    app, _, oauth = create_app(store)
    try:
        uvicorn.run(app, host="0.0.0.0", port=8082, proxy_headers=False, access_log=False,
                    log_config=None, log_level="critical", limit_concurrency=8, backlog=16, timeout_keep_alive=5)
    finally:
        oauth.cimd.close()
        store.close()


if __name__ == "__main__":
    main()
