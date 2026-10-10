"""Refresh/consent tests use only ephemeral identities and synthetic tokens."""
import asyncio
import copy
import json
import secrets
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from mcp_bridge import cimd
from mcp_bridge.config import ORIGIN, RESOURCE, SCOPES, READ_SCOPES, OAUTH_SCOPES, REFRESH_IDLE_TTL, REFRESH_ABSOLUTE_TTL
from mcp_bridge.oauth import LibraryRequest, OAuth
from mcp_bridge.server import Verifier
from mcp_bridge.store import Store, digest
from mcp_bridge.tests.test_security import DOC, FixtureCIMD, SecurityTests


class RefreshTests(SecurityTests):
    def consent_code(self, persistent=True, **changes):
        response = self.client.get('/oauth/authorize', params=self.authdata(**changes))
        self.assertEqual(response.status_code, 302)
        response = self.action('consent', approve=True, persistent=persistent,
                               consent_id=self.status()['pending_consent_id'])
        self.assertEqual(response.status_code, 200)
        return parse_qs(urlsplit(response.json()['redirect']).query)['code'][0]

    def durable(self, **changes):
        response = self.exchange(self.consent_code(**changes))
        self.assertEqual(response.status_code, 200)
        value = response.json()
        self.assertIn('refresh_token', value)
        self.assertEqual(value['expires_in'], 900)
        return value

    def refresh(self, value, **changes):
        data = {'grant_type':'refresh_token', 'client_id':cimd.STABLE,
                'resource':RESOURCE, 'refresh_token':value}
        data.update(changes)
        data = {key:value for key,value in data.items() if value is not None}
        return self.client.post('/oauth/token', data=data)

    def verify(self, value):
        return asyncio.run(Verifier(self.store).verify_token(value))

    def family(self, token):
        return token['refresh_token'].split('.')[1]

    def count(self, kind):
        return self.store.db.execute('SELECT count(*) FROM records WHERE kind=?',(kind,)).fetchone()[0]

    def test_discovery_and_public_client_declare_refresh_without_resource_scope_expansion(self):
        metadata = self.client.get('/.well-known/oauth-authorization-server').json()
        self.assertEqual(metadata['grant_types_supported'], ['authorization_code','refresh_token'])
        self.assertEqual(metadata['scopes_supported'], OAUTH_SCOPES)
        self.assertEqual(self.client.get('/.well-known/oauth-protected-resource/mcp').json()['scopes_supported'], SCOPES)
        self.assertNotIn('offline_access', self.client.post('/mcp',json={}).headers['www-authenticate'])
        self.assertEqual(cimd.validate(cimd.STABLE,DOC)['grant_types'],['authorization_code','refresh_token'])

    def test_existing_and_new_unchecked_consent_never_create_refresh(self):
        self.enroll();legacy=self.token()
        response=self.exchange(self.consent_code(persistent=False,scope=' '.join(OAUTH_SCOPES)))
        self.assertEqual(response.status_code,200)
        self.assertNotIn('refresh_token',response.json())
        self.assertEqual(response.json()['scope'],' '.join(SCOPES))
        self.assertEqual(self.count('refresh_family'),0)
        self.assertNotIn('refresh_family',self.store.get('token',digest(legacy)))

    def test_read_only_choice_stays_read_only_and_offline_is_not_mcp_authority(self):
        self.enroll();token=self.durable(scope=' '.join(READ_SCOPES+['offline_access']))
        access=self.verify(token['access_token'])
        self.assertEqual(access.scopes,READ_SCOPES)
        response=self.refresh(token['refresh_token'])
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['scope'],' '.join(READ_SCOPES+['offline_access']))
        self.assertEqual(self.verify(response.json()['access_token']).scopes,READ_SCOPES)

    def test_explicit_duration_opt_in_works_with_unchanged_six_data_scopes(self):
        self.enroll();token=self.durable()
        self.assertEqual(token['scope'],' '.join(SCOPES))
        self.assertEqual(self.verify(token['access_token']).scopes,SCOPES)
        self.assertEqual(self.count('refresh_family'),1)

    def test_rotation_is_single_use_bounded_and_keeps_exact_bindings(self):
        self.enroll();token=self.durable();family=self.family(token)
        first=self.store.get('refresh_family',family)
        for rotation in range(1,9):
            old=token['refresh_token'];response=self.refresh(old)
            self.assertEqual(response.status_code,200);token=response.json()
            self.assertNotEqual(token['refresh_token'],old)
            self.assertEqual(self.family(token),family)
            self.assertEqual(token['expires_in'],900)
            row=self.store.get('refresh_family',family)
            for key in ('client_id','resource','subject','issuer','scope','created_at','absolute_expires_at','proof_hash'):
                self.assertEqual(row[key],first[key])
            self.assertEqual(row['rotations'],rotation)
            self.assertEqual(self.count('refresh_family'),1)
            self.assertEqual(set(row),set(first))

    def test_replay_revokes_family_and_all_its_access_tokens_only(self):
        self.enroll();old=self.durable();unrelated=self.durable();legacy=self.token()
        current=self.refresh(old['refresh_token']).json()
        self.assertEqual(self.refresh(old['refresh_token']).status_code,400)
        self.assertIsNone(self.store.get('refresh_family',self.family(old)))
        for token in (old,current):self.assertIsNone(self.verify(token['access_token']))
        self.assertEqual(self.refresh(current['refresh_token']).status_code,400)
        self.assertIsNotNone(self.verify(unrelated['access_token']))
        self.assertIsNotNone(self.verify(legacy))
        self.assertEqual(self.refresh(unrelated['refresh_token']).status_code,200)

    def test_wrong_proof_unknown_family_or_malformed_token_cannot_revoke_connection(self):
        self.enroll();token=self.durable();parts=token['refresh_token'].split('.')
        bad_proof='r1.'+parts[1]+'.'+secrets.token_urlsafe(32)+'.'+parts[3]
        bad_family='r1.'+('0'*24)+'.'+parts[2]+'.'+parts[3]
        for value in ('', 'x'*43, token['refresh_token']+'.extra', '\u00e4'*43, bad_proof, bad_family, 'x'*32769):
            self.assertIn(self.refresh(value).status_code,(400,413))
            self.assertIsNotNone(self.verify(token['access_token']))
        self.assertEqual(self.refresh(token['refresh_token']).status_code,200)

    def test_valid_family_proof_but_changed_rotating_secret_is_replay(self):
        self.enroll();token=self.durable();parts=token['refresh_token'].split('.')
        forged='.'.join(parts[:-1]+[secrets.token_urlsafe(32)])
        self.assertEqual(self.refresh(forged).status_code,400)
        self.assertIsNone(self.verify(token['access_token']))

    def test_wrong_resource_or_client_does_not_consume_or_revoke_refresh(self):
        self.enroll();token=self.durable()
        for changes in ({'resource':ORIGIN+'/other'}, {'resource':None}, {'client_id':'https://attacker.invalid/client.json'},
                        {'client_id':cimd.STABLE,'redirect_uri':'https://attacker.invalid'}, {'client_id':None}):
            self.assertEqual(self.refresh(token['refresh_token'],**changes).status_code,400)
            self.assertIsNotNone(self.verify(token['access_token']))
        other='https://chatgpt.com/oauth/synthetic-client/client.json'
        document=copy.deepcopy(DOC);document['client_id']=other;document['redirect_uris']=[cimd.expected_redirect(other)]
        self.oauth.cimd.cache[other]=(10**15,cimd.validate(other,document))
        self.assertEqual(self.refresh(token['refresh_token'],client_id=other).status_code,400)
        self.assertEqual(self.refresh(token['refresh_token']).status_code,200)

    def test_refresh_cannot_expand_duplicate_or_omit_base_scope(self):
        self.enroll();token=self.durable(scope=' '.join(READ_SCOPES))
        for scope in (' '.join(SCOPES), 'bridge:read mail:admin', 'bridge:read bridge:read', 'mail:read',''):
            self.assertEqual(self.refresh(token['refresh_token'],scope=scope).status_code,400)
            self.assertIsNotNone(self.verify(token['access_token']))
        self.assertEqual(self.refresh(token['refresh_token']).status_code,200)

    def test_downscoping_is_permanent_and_invalidates_older_broader_access(self):
        self.enroll();old=self.durable()
        response=self.refresh(old['refresh_token'],scope='bridge:read mail:read')
        self.assertEqual(response.status_code,200);current=response.json()
        self.assertEqual(current['scope'],'bridge:read mail:read')
        self.assertIsNone(self.verify(old['access_token']))
        self.assertEqual(self.verify(current['access_token']).scopes,['bridge:read','mail:read'])
        self.assertEqual(self.refresh(current['refresh_token'],scope=' '.join(SCOPES)).status_code,400)
        self.assertEqual(self.refresh(current['refresh_token']).status_code,200)

    def test_access_expires_after_fifteen_minutes_but_refresh_remains_usable(self):
        self.enroll();token=self.durable();self.offset+=900
        self.assertIsNone(self.verify(token['access_token']))
        response=self.refresh(token['refresh_token']);self.assertEqual(response.status_code,200)
        self.assertIsNotNone(self.verify(response.json()['access_token']))

    def test_idle_expiry_and_sliding_window(self):
        self.enroll();token=self.durable();first=self.store.get('refresh_family',self.family(token))
        self.offset+=REFRESH_IDLE_TTL-100
        response=self.refresh(token['refresh_token']);self.assertEqual(response.status_code,200);current=response.json()
        row=self.store.get('refresh_family',self.family(current))
        self.assertGreater(row['idle_expires_at'],first['idle_expires_at'])
        self.offset+=REFRESH_IDLE_TTL
        self.assertEqual(self.refresh(current['refresh_token']).status_code,400)
        self.assertIsNone(self.verify(current['access_token']))

    def test_absolute_expiry_survives_regular_refresh_and_caps_idle_window(self):
        self.enroll();token=self.durable();first=self.store.get('refresh_family',self.family(token))
        for _ in range(4):
            self.offset+=20*86400
            response=self.refresh(token['refresh_token']);self.assertEqual(response.status_code,200);token=response.json()
        row=self.store.get('refresh_family',self.family(token))
        self.assertEqual(row['absolute_expires_at'],first['absolute_expires_at'])
        self.assertEqual(row['idle_expires_at'],row['absolute_expires_at'])
        self.offset+=10*86400
        self.assertEqual(self.refresh(token['refresh_token']).status_code,400)
        self.assertIsNone(self.verify(token['access_token']))

    def test_owner_issuer_resource_and_scope_corruption_fail_closed(self):
        self.enroll();token=self.durable();family=self.family(token);original=self.store.get('refresh_family',family)
        for changes in ({'subject':'other-owner'}, {'issuer':'https://attacker.invalid'}, {'resource':ORIGIN+'/other'}, {'scope':'bridge:read mail:admin'}):
            self.store.put('refresh_family',family,{**original,**changes},REFRESH_IDLE_TTL)
            self.assertIsNone(self.verify(token['access_token']))
            self.assertEqual(self.refresh(token['refresh_token']).status_code,400)
        self.store.put('refresh_family',family,original,REFRESH_IDLE_TTL)
        self.assertEqual(self.refresh(token['refresh_token']).status_code,200)

    def test_concurrent_single_use_detects_second_request_and_revokes_winner(self):
        self.enroll();token=self.durable();barrier=threading.Barrier(2)
        data={'grant_type':'refresh_token','client_id':cimd.STABLE,'resource':RESOURCE,'refresh_token':token['refresh_token']}
        def redeem(_):
            barrier.wait()
            with self.store.transaction():
                response=self.oauth.create_token_response(LibraryRequest('POST',ORIGIN+'/oauth/token',data))
                return response.status_code,json.loads(response.body)
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(redeem,range(2)))
        self.assertEqual(sorted(result[0] for result in results),[200,400])
        winner=next(body for status,body in results if status==200)
        self.assertIsNone(self.verify(winner['access_token']))
        self.assertIsNone(self.verify(token['access_token']))
        self.assertEqual(self.count('refresh_family'),0)

    def test_failed_atomic_access_save_keeps_previous_refresh_usable(self):
        self.enroll();token=self.durable();family=self.family(token);before=self.store.get('refresh_family',family)
        original=self.store.put
        def fail_access(kind,*args,**kwargs):
            if kind=='token':raise ValueError('synthetic_storage_failure')
            return original(kind,*args,**kwargs)
        with patch.object(self.store,'put',side_effect=fail_access):
            self.assertEqual(self.refresh(token['refresh_token']).status_code,400)
        self.assertEqual(self.store.get('refresh_family',family),before)
        self.assertIsNotNone(self.verify(token['access_token']))
        self.assertEqual(self.refresh(token['refresh_token']).status_code,200)

    def test_restart_persists_hashes_rotation_and_replay_detection(self):
        self.enroll();old=self.durable();current=self.refresh(old['refresh_token']).json()
        restarted=Store(self.store.path,clock=self.store.clock)
        try:
            oauth=OAuth(restarted,FixtureCIMD())
            def redeem(value):
                data={'grant_type':'refresh_token','client_id':cimd.STABLE,'resource':RESOURCE,'refresh_token':value}
                with restarted.transaction():return oauth.create_token_response(LibraryRequest('POST',ORIGIN+'/oauth/token',data))
            response=redeem(current['refresh_token']);self.assertEqual(response.status_code,200)
            self.assertEqual(redeem(old['refresh_token']).status_code,400)
            self.assertIsNone(asyncio.run(Verifier(restarted).verify_token(json.loads(response.body)['access_token'])))
        finally:restarted.close()

    def test_storage_and_owner_list_never_contain_raw_refresh_proof_or_access(self):
        self.enroll();old=self.durable();current=self.refresh(old['refresh_token']).json()
        stored='\n'.join(self.store.db.iterdump())
        response=self.client.get('/auth/grants');self.assertEqual(response.status_code,200)
        displayed=response.text
        for token in (old,current):
            for value in (token['access_token'],token['refresh_token'],token['refresh_token'].split('.')[2]):
                self.assertNotIn(value,stored);self.assertNotIn(value,displayed)
        self.assertNotIn('hash',displayed)
        self.assertEqual(response.json()['policy']['absolute_days'],90)

    def test_four_connection_cap_is_atomic_and_slot_returns_after_revocation(self):
        self.enroll();tokens=[self.durable() for _ in range(4)]
        code=self.consent_code();self.assertEqual(self.exchange(code).status_code,400)
        self.assertEqual(self.count('refresh_family'),4)
        for token in tokens:self.assertIsNotNone(self.verify(token['access_token']))
        self.assertEqual(self.action('grants/revoke',grant_id=self.family(tokens[0])).status_code,200)
        response=self.exchange(code);self.assertEqual(response.status_code,200)
        self.assertEqual(self.count('refresh_family'),4)

    def test_per_connection_revoke_is_recent_owner_bound_and_invalidates_all_access(self):
        self.enroll();old=self.durable();current=self.refresh(old['refresh_token']).json();other=self.durable();legacy=self.token()
        response=self.action('grants/revoke',grant_id=self.family(current));self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['access_tokens_revoked'],2)
        self.assertIsNone(self.verify(old['access_token']));self.assertIsNone(self.verify(current['access_token']))
        self.assertEqual(self.refresh(current['refresh_token']).status_code,400)
        self.assertIsNotNone(self.verify(other['access_token']));self.assertIsNotNone(self.verify(legacy))
        self.assertEqual(len(self.client.get('/auth/grants').json()['connections']),1)

    def test_revoke_denies_bearer_only_bad_csrf_cross_origin_unknown_or_stale_owner(self):
        self.enroll();token=self.durable();family=self.family(token);csrf=self.status()['csrf']
        self.assertEqual(self.client.get('/auth/grants',headers={'Authorization':'Bearer '+token['access_token']}).status_code,401)
        for data,headers in (({'csrf':'wrong','grant_id':family},{}),
                             ({'csrf':csrf,'grant_id':family},{'Origin':'https://attacker.invalid'}),
                             ({'csrf':csrf,'grant_id':family},{'Authorization':'Bearer '+token['access_token']}),
                             ({'csrf':csrf,'grant_id':family,'extra':True},{}),
                             ({'csrf':csrf,'grant_id':'../token'},{}),({'csrf':csrf,'grant_id':'0'*24},{})):
            self.assertIn(self.client.post('/auth/grants/revoke',json=data,headers=headers).status_code,(400,403))
        self.assertIsNotNone(self.verify(token['access_token']))
        self.offset+=300
        self.assertEqual(self.client.get('/auth/grants').status_code,401)
        self.assertEqual(self.action('grants/revoke',grant_id=family).status_code,400)
        self.assertEqual(self.action('revoke').status_code,400)
        self.assertEqual(self.refresh(token['refresh_token']).status_code,200)

    def test_anonymous_list_and_revoke_fail_without_creating_grants(self):
        self.assertEqual(self.client.get('/auth/grants').status_code,401)
        self.assertEqual(self.client.post('/auth/grants/revoke',json={}).status_code,400)
        self.assertEqual(self.count('refresh_family'),0)

    def test_global_revoke_deletes_refresh_access_and_pending_code(self):
        self.enroll();token=self.durable();legacy=self.token();code=self.consent_code()
        self.assertEqual(self.client.get('/oauth/authorize',params=self.authdata()).status_code,302)
        self.assertEqual(self.action('revoke').status_code,200)
        for kind in ('refresh_family','token','code','pending'):self.assertEqual(self.count(kind),0)
        self.assertEqual(self.refresh(token['refresh_token']).status_code,400)
        self.assertIsNone(self.verify(legacy));self.assertEqual(self.exchange(code).status_code,400)

    def test_browser_logout_preserves_explicit_durable_grant(self):
        self.enroll();token=self.durable();self.assertEqual(self.action('logout').status_code,200)
        self.assertEqual(self.client.get('/auth/grants').status_code,401)
        self.assertEqual(self.refresh(token['refresh_token']).status_code,200)

    def test_recovery_revokes_refresh_but_keeps_irreversible_operation_receipts(self):
        self.enroll();token=self.durable()
        receipt,_=self.store.reserve_operation('synthetic-mail-send','fixture-refresh-recovery-0001',{'fixture':True})
        self.store.finish_operation(receipt,{'completed':True})
        self.store.recovery_reset()
        self.assertEqual(self.refresh(token['refresh_token']).status_code,400)
        self.assertIsNone(self.verify(token['access_token']))
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM operations').fetchone()[0],1)

    def test_client_without_refresh_declaration_cannot_gain_persistent_grant(self):
        self.enroll();document=copy.deepcopy(DOC);document['grant_types']=['authorization_code']
        self.oauth.cimd.cache[cimd.STABLE]=(10**15,cimd.validate(cimd.STABLE,document))
        self.assertEqual(self.client.get('/oauth/authorize',params=self.authdata()).status_code,302)
        state=self.status();self.assertFalse(state['pending_refresh_available'])
        self.assertEqual(self.action('consent',approve=True,persistent=True,consent_id=state['pending_consent_id']).status_code,400)
        self.assertEqual(self.count('refresh_family'),0)
        self.assertNotIn('refresh_token',self.exchange(self.consent_code(persistent=False)).json())

    def test_changed_pending_request_requires_its_own_consent_id(self):
        self.enroll();self.client.get('/oauth/authorize',params=self.authdata(scope=' '.join(READ_SCOPES)))
        old=self.status()['pending_consent_id']
        self.client.get('/oauth/authorize',params=self.authdata())
        self.assertNotEqual(old,self.status()['pending_consent_id'])
        self.assertEqual(self.action('consent',approve=True,persistent=True,consent_id=old).status_code,400)
        self.assertEqual(self.count('code'),0);self.assertEqual(self.count('refresh_family'),0)

    def test_duration_checkbox_is_strict_bool_and_cannot_be_injected_at_token_endpoint(self):
        self.enroll();self.client.get('/oauth/authorize',params=self.authdata())
        state=self.status()
        for value in ('true',1,None,[],{}):
            self.assertEqual(self.action('consent',approve=True,persistent=value,consent_id=state['pending_consent_id']).status_code,400)
        code=self.code()
        self.assertEqual(self.exchange(code,persistent='true').status_code,400)
        response=self.exchange(code);self.assertEqual(response.status_code,200);self.assertNotIn('refresh_token',response.json())


def load_tests(loader,tests,pattern):
    # Imported base fixture tests already run in test_security.py.
    return unittest.TestSuite(RefreshTests(name) for name in RefreshTests.__dict__ if name.startswith('test_'))
