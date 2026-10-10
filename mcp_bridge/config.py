"""One exact HTTPS origin and RP ID. Invalid or missing configuration fails closed."""
import os
import re
from urllib.parse import urlsplit


def deployment_identity(value, rp_id=None):
    if not isinstance(value, str) or not value or len(value) > 253 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise RuntimeError('public_origin_required')
    try:
        parsed=urlsplit(value)
        domain=parsed.hostname or ''
        port=parsed.port
    except ValueError:
        raise RuntimeError('invalid_public_origin') from None
    labels=domain.split('.')
    if (parsed.scheme != 'https' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or
        len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels) or
        not re.search(r'[a-z]',labels[-1]) or domain.endswith(('.localhost','.local')) or
        port is not None and not 1 <= port <= 65535 or rp_id is not None and rp_id != domain):
        raise RuntimeError('invalid_public_origin_or_rp_id')
    host=domain + (':'+str(port) if port is not None and port != 443 else '')
    origin='https://'+host
    if value != origin: raise RuntimeError('public_origin_must_be_canonical')
    return domain,origin,host


DOMAIN,ORIGIN,HOST=deployment_identity(os.environ.get('MCP_PUBLIC_ORIGIN'),os.environ.get('MCP_RP_ID'))
RESOURCE=ORIGIN+'/mcp'
READ_SCOPES=['bridge:read','mail:read','calendars:read']
SCOPES=READ_SCOPES+['mail:write','mail:send','calendars:write','contacts:read']
OAUTH_SCOPES=SCOPES+['offline_access']
REFRESH_IDLE_TTL=30*86400
REFRESH_ABSOLUTE_TTL=90*86400
MAX_REFRESH_FAMILIES=4
DEFAULT_SCOPE=' '.join(READ_SCOPES)
IDENTITY_FILE='/run/identity/identity.sqlite3'
COOKIE='__Host-mcpbridge'
CODE_TTL=60
TOKEN_TTL=900
SESSION_TTL=900
CHALLENGE_TTL=180
SETUP_TTL=600
APPROVAL_TTL=300
MAX_BODY=32768
