"""Bounded refresh families. Only hashes of bearer material reach SQLite."""
import hmac
import json
import re
import secrets
from dataclasses import dataclass

from authlib.oauth2.rfc6749 import TokenMixin

from .config import MAX_REFRESH_FAMILIES, OAUTH_SCOPES, ORIGIN, RESOURCE, REFRESH_ABSOLUTE_TTL, REFRESH_IDLE_TTL
from .store import digest

FORMAT = re.compile(r'r1\.([a-f0-9]{24})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})\Z')


@dataclass(repr=False)
class RefreshCredential(TokenMixin):
    family_id: str
    proof: str
    record: dict

    def check_client(self,client):return self.record['client_id']==client.get_client_id()
    def get_scope(self):return self.record['scope']


class Grants:
    def __init__(self,store):self.store=store

    def active(self,family_id):
        with self.store.lock:
            row=self.store.get('refresh_family',family_id)
            if (not row or row['subject']!=self.store.owner or not self.store.credentials() or
                row['issuer']!=ORIGIN or row['resource']!=RESOURCE or
                min(row['idle_expires_at'],row['absolute_expires_at'])<=self.store.clock() or
                not set(row['scope'].split())<=set(OAUTH_SCOPES)):
                return None
            return row

    def issue(self,context,client_id,scope):
        # The OAuth endpoint holds one SQLite transaction through issue/save.
        self.store.purge()
        if self.store.db.execute("SELECT count(*) FROM records WHERE kind='refresh_family'").fetchone()[0]>=MAX_REFRESH_FAMILIES:
            raise ValueError('persistent_grant_capacity')
        family_id=secrets.token_hex(12);proof=secrets.token_urlsafe(32)
        value='r1.'+family_id+'.'+proof+'.'+secrets.token_urlsafe(32)
        now=self.store.clock()
        record={'client_id':client_id,'scope':scope,'resource':context.resource,'subject':context.subject,'issuer':ORIGIN,
                'created_at':now,'last_used_at':now,'idle_expires_at':now+REFRESH_IDLE_TTL,
                'absolute_expires_at':now+REFRESH_ABSOLUTE_TTL,'proof_hash':digest(proof),
                'current_hash':digest(value),'rotations':0}
        self.store.put('refresh_family',family_id,record,REFRESH_IDLE_TTL,maximum=MAX_REFRESH_FAMILIES)
        return value,family_id

    def authenticate(self,value,client_id,resource):
        match=FORMAT.fullmatch(value) if isinstance(value,str) else None
        if not match:return None
        family_id,proof,_=match.groups();row=self.active(family_id)
        if (not row or row['client_id']!=client_id or row['resource']!=resource or
            not hmac.compare_digest(row['proof_hash'],digest(proof))):return None
        # The hash-verified family proof prevents a guessed or modified family
        # identifier revoking another grant. Old generations keep that proof,
        # so replay is detectable without accumulating rotated-token history.
        if not hmac.compare_digest(row['current_hash'],digest(value)):
            self.revoke(family_id)
            return None
        return RefreshCredential(family_id,proof,row)

    def rotate(self,credential,scope):
        row=self.active(credential.family_id)
        if not row or row['current_hash']!=credential.record['current_hash']:
            raise ValueError('refresh_state_changed')
        value='r1.'+credential.family_id+'.'+credential.proof+'.'+secrets.token_urlsafe(32)
        now=self.store.clock();row.update(scope=scope,current_hash=digest(value),last_used_at=now,
            idle_expires_at=min(now+REFRESH_IDLE_TTL,row['absolute_expires_at']),rotations=row['rotations']+1)
        self.store.put('refresh_family',credential.family_id,row,row['idle_expires_at']-now,maximum=MAX_REFRESH_FAMILIES)
        return value,credential.family_id

    def revoke(self,family_id):
        self.store.delete('refresh_family',family_id)
        return self.store.db.execute("DELETE FROM records WHERE kind='token' AND json_extract(value,'$.refresh_family')=?",(family_id,)).rowcount

    def listings(self):
        with self.store.lock:
            self.store.purge()
            rows=self.store.db.execute("SELECT key,value FROM records WHERE kind='refresh_family' ORDER BY expiry").fetchall()
            return [{'id':row['key'],**{key:value for key,value in json.loads(row['value']).items() if key in
                {'client_id','scope','created_at','last_used_at','idle_expires_at','absolute_expires_at'}}} for row in rows]

    @staticmethod
    def policy():
        return {'access_token_seconds':900,'idle_days':30,'absolute_days':90,'maximum_active_connections':MAX_REFRESH_FAMILIES,
                'rotation_required':True,'replay_revokes_family_and_access_tokens':True}
