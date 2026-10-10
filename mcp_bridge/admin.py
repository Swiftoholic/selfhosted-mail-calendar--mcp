"""Human-operated private SSH CLI. No HTTP reset or reusable setup password."""
import re
import sys

from .config import IDENTITY_FILE, ORIGIN
from .store import Store


def main():
    if not sys.stdin.isatty() or sys.argv[1:] not in (["bootstrap"], ["recover"]):
        raise SystemExit("Only interactive SSH use: python -m mcp_bridge.admin bootstrap|recover")
    store = Store(IDENTITY_FILE)
    try:
        if sys.argv[1] == "recover":
            print("All owner passkeys, sessions and OAuth grants will be revoked.")
            if input("To confirm your own recovery request, type RESET MCP OWNER: ") != "RESET MCP OWNER":
                raise SystemExit("Cancelled; no changes.")
            store.recovery_reset()
            print("Reset complete. Open the login page yourself, then approve its exact new request.")
            return
        print("Approve only the fingerprint visible in YOUR browser at " + ORIGIN + "/login")
        fingerprint = re.sub(r"[\s-]", "", input("Your browser fingerprint: ")).lower()
        if not re.fullmatch(r"[0-9a-f]{32}", fingerprint):
            raise SystemExit("Invalid fingerprint; no changes.")
        store.approve_bootstrap(fingerprint)
        print("Only that browser request is approved for 5 minutes. Register the passkey yourself.")
    except ValueError:
        raise SystemExit("Request unavailable or owner already enrolled; no approval issued.") from None
    finally:
        store.close()


if __name__ == "__main__":
    main()
