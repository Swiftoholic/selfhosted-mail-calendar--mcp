"""Synthetic wire-name roundtrips only; no provider network or real accounts."""
import base64
import tempfile
import unittest
from pathlib import Path

from mcp_bridge.accounts import AccountSecrets, bind_id
from mcp_bridge.mail_ops import MailOperations, folder_display_name, folder_id
from mcp_bridge.operations import Operations
from mcp_bridge.store import Store
from mcp_bridge.tests.test_writes import FixtureSecrets, IMAPFixture


def encode_fixture_label(label):
    """Independent test encoder; never used to replace a server wire name."""
    pieces,shifted=[],[]
    def flush():
        if shifted:
            encoded=base64.b64encode(''.join(shifted).encode('utf-16-be')).decode('ascii')
            pieces.append('&'+encoded.rstrip('=').replace('/',',')+'-');shifted.clear()
    for character in label:
        if 32<=ord(character)<=126:
            flush();pieces.append('&-' if character=='&' else character)
        else:shifted.append(character)
    flush();return ''.join(pieces)


class LabelIMAP(IMAPFixture):
    names=('INBOX','Entw&APw-rfe','Gel&APY-scht','R&-D + Notes','Folder\\Quoted"Name')
    def __init__(self):
        super().__init__();self.selected_wire=[]
    def list(self):
        rows=[]
        for name in self.names:
            flags='\\Trash' if name=='Gel&APY-scht' else '\\HasNoChildren'
            rows.append(('('+flags+') "/" '+self._quote(name)).encode('ascii'))
        return 'OK',rows
    def select(self,name,readonly=False):
        self.selected_wire.append((name,readonly));return 'OK',[]


class FolderLabelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(Path(self.temp.name)/'identity.sqlite3')
        self.imap=LabelIMAP();self.mail=MailOperations(FixtureSecrets(),self.store,self.imap.factory)
    def tearDown(self):
        self.store.db.close();self.temp.cleanup()

    def test_observed_german_labels(self):
        self.assertEqual(folder_display_name('Entw&APw-rfe'),'Entwürfe')
        self.assertEqual(folder_display_name('Gel&APY-scht'),'Gelöscht')

    def test_ascii_ampersands_and_literal_plus(self):
        self.assertEqual(folder_display_name('R&-D + Notes'),'R&D + Notes')
        self.assertEqual(folder_display_name('INBOX'),'INBOX')
        self.assertEqual(folder_display_name('Folder\\Quoted"Name'),'Folder\\Quoted"Name')

    def test_multilingual_and_surrogate_pair_roundtrips(self):
        for label in ('Entwürfe','Gelöscht','R&D/日本語 + 中文','📬 Archiv/ÄÖÜß','台北/旅行','a&b&c','Ü😀& Ende'):
            with self.subTest(label=label):self.assertEqual(folder_display_name(encode_fixture_label(label)),label)
        self.assertEqual(folder_display_name('~peter/mail/&U,BTFw-/&ZeVnLIqe-'),'~peter/mail/台北/日本語')

    def test_invalid_or_control_encoding_preserves_entire_wire_label(self):
        for name in ('Broken&','Broken&APw','&A-','&APw=-','&AP/-','&APx-','&2AA-','&AAA-','&AA0ACg-','&AEk-','R&-D/Bad&*-/End'):
            with self.subTest(name=name):self.assertEqual(folder_display_name(name),name)

    def test_listing_changes_only_display_label_preserves_ids_and_flags(self):
        original=self.mail.folders(self.imap);display=self.mail.list_folders({})['items']
        for raw,shown in zip(original,display):
            self.assertEqual({k:v for k,v in raw.items() if k!='name'},{k:v for k,v in shown.items() if k!='name'})
            self.assertEqual(raw['id'],folder_id(raw['name']))
        self.assertEqual(display[1]['name'],'Entwürfe');self.assertEqual(display[2]['name'],'Gelöscht')
        self.assertEqual(original[1]['name'],'Entw&APw-rfe')
        self.assertTrue(display[2]['is_trash']);self.assertEqual(display[2]['data_trust'],'untrusted')

    def test_displayed_id_roundtrip_selects_original_wire_name_read_only(self):
        shown=self.mail.list_folders({})['items'][1]
        self.mail.local.mailbox_id=shown['id']
        with self.mail.opened():pass
        self.assertEqual(self.imap.selected_wire,[('"Entw&APw-rfe"',True)])
        self.assertFalse(any(command[0] in {'MOVE','STORE','EXPUNGE'} for command in self.imap.commands))

    def test_revision_bound_display_id_roundtrip_keeps_raw_identity(self):
        secret_dir=Path(self.temp.name)/'secrets';secret_dir.mkdir(mode=0o700)
        secrets=AccountSecrets(secret_dir);saved=secrets.persist('mail','synthetic@example.invalid','SYNTHETIC_ONLY_NO_ACCESS_0001',None)
        mail=MailOperations(secrets,self.store,self.imap.factory);backend=Operations(self.store,secrets,mail=mail)
        shown=backend.call('POST','/mcp/mail/folders',{})['items'][1]
        self.assertEqual(shown['name'],'Entwürfe')
        self.assertEqual(bind_id(shown['id'],saved['revision'],'mailbox'),folder_id('Entw&APw-rfe'))
        with secrets.operation('mail'):
            mail.local.mailbox_id=bind_id(shown['id'],saved['revision'],'mailbox')
            with mail.opened():pass
        self.assertEqual(self.imap.selected_wire,[('"Entw&APw-rfe"',True)])


def load_tests(loader,tests,pattern):
    # Imported fixtures contain no tests; keep this suite narrowly scoped.
    return loader.loadTestsFromTestCase(FolderLabelTests)
