"""Duo WebAuthn verification. Only an exact SSH-approved browser can bootstrap."""
import json
import secrets

from webauthn import generate_authentication_options, generate_registration_options, verify_authentication_response, verify_registration_response
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement, UserVerificationRequirement

from .config import CHALLENGE_TTL, DOMAIN, ORIGIN, SESSION_TTL, SETUP_TTL
from .store import b64, digest, unb64


class Identity:
    def __init__(self, store):
        self.store = store

    def new_session(self):
        value = secrets.token_urlsafe(32)
        item = {"csrf": secrets.token_urlsafe(32), "owner": False, "verified_at": 0}
        self.store.put("session", digest(value), item, SESSION_TTL, maximum=128)
        return value, digest(value), item

    def session(self, cookie):
        if not isinstance(cookie, str) or len(cookie) != 43:
            return None
        try:
            key = digest(cookie)
        except UnicodeError:
            return None
        item = self.store.get("session", key)
        return (cookie, key, item) if item else None

    def owner_session(self, item):
        return bool(item and item.get("owner") == self.store.owner and self.store.credentials())

    def recent(self, item):
        return self.owner_session(item) and 0 <= self.store.clock() - item.get("verified_at", 0) < 300

    def setup(self, binding):
        with self.store.transaction():
            if self.store.credentials():
                raise ValueError("owner_already_enrolled")
            session = self.store.get("session", binding)
            if not session:
                raise ValueError("session_expired")
            old = session.get("setup")
            if old and self.store.get("setup", old):
                return old
            fingerprint = secrets.token_hex(16)
            self.store.put("setup", fingerprint, {"binding": binding, "approved_until": 0}, SETUP_TTL, maximum=32)
            session["setup"] = fingerprint
            self.store.put("session", binding, session, SESSION_TTL, maximum=128)
            return fingerprint

    def approved(self, binding, session):
        item = self.store.get("setup", session.get("setup", ""))
        return bool(item and item["binding"] == binding and item["approved_until"] > self.store.clock())

    def registration_options(self, binding, session):
        with self.store.transaction():
            credentials = self.store.credentials()
            if credentials:
                if not self.recent(session) or len(credentials) >= 5:
                    raise ValueError("recent_owner_verification_required")
                mode = "additional"
            else:
                if not self.approved(binding, session):
                    raise ValueError("ssh_approval_required")
                mode = "initial"
            challenge = secrets.token_bytes(32)
            self.store.put("registration", binding, {"binding": binding, "challenge": b64(challenge), "mode": mode}, CHALLENGE_TTL)
            options = generate_registration_options(
            rp_id=DOMAIN, rp_name="Mail and Calendar MCP", user_name="Privater Eigentumer",
                user_display_name="Privater Eigentumer", user_id=unb64(self.store.owner),
                challenge=challenge, timeout=180000,
                exclude_credentials=[PublicKeyCredentialDescriptor(id=unb64(row["id"])) for row in credentials],
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED, require_resident_key=True,
                    user_verification=UserVerificationRequirement.REQUIRED))
            return json.loads(options_to_json(options))

    def authentication_options(self, binding):
        with self.store.transaction():
            if not self.store.credentials():
                raise ValueError("owner_not_enrolled")
            challenge = secrets.token_bytes(32)
            self.store.put("authentication", binding, {"binding": binding, "challenge": b64(challenge)}, CHALLENGE_TTL)
            return json.loads(options_to_json(generate_authentication_options(
                rp_id=DOMAIN, challenge=challenge, timeout=180000,
                user_verification=UserVerificationRequirement.REQUIRED)))

    @staticmethod
    def same_origin(credential):
        data = json.loads(unb64(credential["response"]["clientDataJSON"]))
        if data.get("crossOrigin", False) is not False or data.get("topOrigin", ORIGIN) != ORIGIN:
            raise ValueError("cross_origin_credential")

    def verify(self, kind, binding, session, credential):
        # Commit challenge consumption even on invalid signatures. Failed
        # verification must never roll back into a replayable challenge.
        error = None
        with self.store.transaction():
            try:
                challenge = self.store.consume(kind, binding, binding)
                if not isinstance(credential, dict):
                    raise ValueError("invalid_credential")
                self.same_origin(credential)
                if kind == "registration":
                    credentials = self.store.credentials()
                    if challenge["mode"] == "initial":
                        if credentials or not self.approved(binding, session):
                            raise ValueError("ssh_approval_required")
                    elif not self.recent(session) or len(credentials) >= 5:
                        raise ValueError("recent_owner_verification_required")
                    result = verify_registration_response(
                        credential=credential, expected_challenge=unb64(challenge["challenge"]),
                        expected_rp_id=DOMAIN, expected_origin=ORIGIN,
                        require_user_presence=True, require_user_verification=True)
                    self.store.db.execute("INSERT INTO credentials VALUES(?,?,?,?)",
                                          (b64(result.credential_id), b64(result.credential_public_key), result.sign_count, self.store.clock()))
                    self.store.db.execute("DELETE FROM records WHERE kind='setup'")
                elif kind == "authentication":
                    credential_id = b64(unb64(credential["id"]))
                    known = next((row for row in self.store.credentials() if row["id"] == credential_id), None)
                    if not known or credential["response"].get("userHandle") != self.store.owner:
                        raise ValueError("unknown_credential_or_owner")
                    result = verify_authentication_response(
                        credential=credential, expected_challenge=unb64(challenge["challenge"]),
                        expected_rp_id=DOMAIN, expected_origin=ORIGIN,
                        credential_public_key=unb64(known["public_key"]),
                        credential_current_sign_count=known["counter"], require_user_verification=True)
                    self.store.db.execute("UPDATE credentials SET counter=? WHERE id=?", (result.new_sign_count, credential_id))
                else:
                    raise ValueError("invalid_challenge_type")
                session = {**session, "owner": self.store.owner, "verified_at": self.store.clock(),
                           "csrf": secrets.token_urlsafe(32)}
                self.store.put("session", binding, session, SESSION_TTL, maximum=128)
            except Exception:
                error = "passkey_verification_failed"
        if error:
            raise ValueError(error)
        return session
