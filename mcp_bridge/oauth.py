"""Public-client Authlib OAuth; refresh only after explicit new owner consent."""
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from authlib.oauth2.rfc6749 import AuthorizationCodeMixin, AuthorizationServer, ClientMixin, InvalidRequestError, InvalidScopeError, OAuth2Request
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant, RefreshTokenGrant
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc7636 import CodeChallenge
from starlette.responses import JSONResponse, Response

from .cimd import expected_redirect
from .config import CODE_TTL, DEFAULT_SCOPE, ORIGIN, RESOURCE, SCOPES, OAUTH_SCOPES, TOKEN_TTL
from .grants import Grants
from .store import digest


class Client(ClientMixin):
    def __init__(self, metadata):
        self.metadata = metadata

    def get_client_id(self):
        return self.metadata["client_id"]

    def get_default_redirect_uri(self):
        return self.metadata["redirect_uri"]

    def get_allowed_scope(self, scope):
        scope = scope or DEFAULT_SCOPE
        requested = scope.split()
        return scope if len(requested) == len(set(requested)) and set(requested) <= set(OAUTH_SCOPES) and "bridge:read" in requested else None

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri == self.get_default_redirect_uri()

    def check_client_secret(self, client_secret):
        return False

    def check_endpoint_auth_method(self, method, endpoint):
        return endpoint == "token" and method == "none"

    def check_response_type(self, response_type):
        return response_type == "code"

    def check_grant_type(self, grant_type):
        return grant_type in self.metadata.get('grant_types',['authorization_code'])


@dataclass
class Code(AuthorizationCodeMixin):
    key: str
    client_id: str
    redirect_uri: str
    scope: str
    resource: str
    code_challenge: str
    code_challenge_method: str
    subject: str
    persistent: bool = False

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope


class S256Only(CodeChallenge):
    DEFAULT_CODE_CHALLENGE_METHOD = "S256"
    SUPPORTED_CODE_CHALLENGE_METHOD = ["S256"]

    def validate_code_challenge(self, grant, redirect_uri):
        data = grant.request.payload.data
        if not data.get("code_challenge") or data.get("code_challenge_method") != "S256":
            raise InvalidRequestError("PKCE S256 is mandatory")
        super().validate_code_challenge(grant, redirect_uri)


class CodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    def save_authorization_code(self, code, request):
        data = request.payload.data
        self.server.store.put("code", digest(code), {
            "client_id": request.client.get_client_id(), "redirect_uri": data["redirect_uri"],
            "scope": request.scope, "resource": data["resource"], "subject": request.user,
            "code_challenge": data["code_challenge"], "code_challenge_method": "S256",
            "persistent": getattr(request,'owner_persistent',False) is True,
        }, CODE_TTL)

    def query_authorization_code(self, code, client):
        try:
            key = digest(code)
        except (UnicodeError, AttributeError):
            return None
        item = self.server.store.get("code", key)
        if not item or item["client_id"] != client.get_client_id():
            return None
        if self.request.payload.data.get("resource") != item["resource"]:
            return None
        return Code(key=key, **item)

    def delete_authorization_code(self, authorization_code):
        self.server.store.delete("code", authorization_code.key)

    def authenticate_user(self, authorization_code):
        store = self.server.store
        return store.owner if authorization_code.subject == store.owner and store.credentials() else None


class LibraryRequest(OAuth2Request):
    def __init__(self, method, uri, data, headers=None):
        super().__init__(method, uri, headers=headers or {})
        self.payload = BasicOAuth2Payload(data)

    @property
    def form(self):
        return self.payload.data if self.method == "POST" else {}

    @property
    def args(self):
        return self.payload.data if self.method == "GET" else {}


class RotatingRefreshGrant(RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['none']
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self,value):
        return self.server.grants.authenticate(value,self.request.client.get_client_id(),self.request.payload.data.get('resource'))

    def _validate_token_scope(self,token):
        super()._validate_token_scope(token)
        scope=self.request.payload.scope
        if scope is not None and (not scope.strip() or not self.request.client.get_allowed_scope(scope)):
            raise InvalidScopeError()

    def authenticate_user(self,credential):
        return self.server.store.owner if self.server.grants.active(credential.family_id) else None

    def revoke_old_credential(self,credential):
        # save_token atomically installed the next hash before this hook.
        pass


class OAuth(AuthorizationServer):
    def __init__(self, store, cimd):
        super().__init__(scopes_supported=OAUTH_SCOPES)
        self.store, self.cimd = store, cimd
        self.grants=Grants(store)
        self.register_grant(CodeGrant, [S256Only(required=True)])
        self.register_grant(RotatingRefreshGrant)
        self.register_token_generator("default", self.token)

    def query_client(self, client_id):
        try:
            expected_redirect(client_id)
            item = self.cimd.cached(client_id)
            return Client(item) if item else None
        except (TypeError, ValueError):
            return None

    def token(self, **kwargs):
        return {"token_type": "Bearer", "access_token": secrets.token_urlsafe(32),
                "expires_in": TOKEN_TTL, "scope": kwargs["scope"]}

    def save_token(self, token, request):
        family_id=None
        if request.payload.grant_type=='refresh_token':
            credential=request.refresh_token;record=credential.record
            token['refresh_token'],family_id=self.grants.rotate(credential,token['scope'])
            resource,subject=record['resource'],record['subject']
        else:
            record=request.authorization_code;resource,subject=record.resource,record.subject
            if record.persistent:
                token['refresh_token'],family_id=self.grants.issue(record,request.client.get_client_id(),token['scope'])
        self.store.put("token", digest(token["access_token"]), {
            "client_id": request.client.get_client_id(), "scope": ' '.join(scope for scope in token['scope'].split() if scope in SCOPES),
            "resource": resource, "subject": subject, "issuer": ORIGIN,
            "expires_at": int(self.store.clock() + TOKEN_TTL),
            **({'refresh_family':family_id} if family_id else {}),
        }, TOKEN_TTL)

    def create_oauth2_request(self, request):
        return request

    def send_signal(self, *args, **kwargs):
        pass

    def handle_response(self, status, body, headers):
        headers = dict(headers)
        location = headers.get("Location")
        if location:
            parts = urlsplit(location)
            base = urlunsplit(parts._replace(query="", fragment=""))
            # Only callbacks derived from validated, cached ChatGPT CIMD.
            with self.cimd.lock:
                allowed = {value[1]["redirect_uri"] for value in self.cimd.cache.values()}
            if base not in allowed or parts.fragment:
                return JSONResponse({"error": "untrusted_redirect"}, status_code=400)
            query = [(k, v) for k, v in parse_qsl(parts.query) if k != "iss"]
            headers["Location"] = urlunsplit(parts._replace(query=urlencode(query + [("iss", ORIGIN)])))
        headers.update({"Cache-Control": "no-store", "Pragma": "no-cache"})
        if isinstance(body, dict):
            return JSONResponse(body, status_code=status, headers=headers)
        return Response(body or "", status_code=status, headers=headers)


def metadata():
    return {"issuer": ORIGIN, "authorization_endpoint": ORIGIN + "/oauth/authorize",
            "token_endpoint": ORIGIN + "/oauth/token", "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": True, "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"], "grant_types_supported": ["authorization_code","refresh_token"],
            "response_types_supported": ["code"], "scopes_supported": OAUTH_SCOPES}
