"""Ephemeral local TLS protocol servers; synthetic data only, no public sockets."""
import contextlib
import base64
import datetime as dt
import http.server
import socket
import socketserver
import ssl
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from bridge.app import CAL, DAV
from bridge.carddav import CARD
from mcp_bridge.tests.test_carddav import VCARD
from mcp_bridge.tests.test_writes import INITIAL, value, xml_response


def certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic protocol fixture')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in ('imap.example.test', 'smtp.example.test', 'calendar.example.test', 'contacts.example.test', 'imap2.example.test', 'smtp2.example.test', 'calendar2.example.test', 'contacts2.example.test')]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = Path(directory)/'fixture-cert.pem', Path(directory)/'fixture-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.minimum_version=ssl.TLSVersion.TLSv1_2;server.load_cert_chain(cert_path,key_path)
    client = ssl.create_default_context(cafile=str(cert_path));client.minimum_version=ssl.TLSVersion.TLSv1_2
    return server, client


class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, handler, context, immediate=True):
        self.context,self.immediate,self.events,self.objects,self.support_starttls=context,immediate,[],{},True
        self.include_acl,self.privilege_mode=True,'allow'
        self.expected_pair=None
        self.move_capability,self.moves=b'MOVE',[]
        super().__init__(('127.0.0.1',0),handler)
    def get_request(self):
        client, peer=super().get_request();client.settimeout(3)
        try:return (self.context.wrap_socket(client,server_side=True) if self.immediate else client),peer
        except Exception:client.close();raise
    def handle_error(self,*unused):
        self.events.append({'error':'synthetic_server_rejected'})


@contextlib.contextmanager
def running(handler, context, immediate=True):
    server=ThreadServer(handler,context,immediate)
    worker=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.02},daemon=True);worker.start()
    try:yield server
    finally:server.shutdown();server.server_close();worker.join(timeout=2)


def fixture_dial(server, expected_host, expected_port):
    def dial(host, port, timeout=8):
        if (host,port)!=(expected_host,expected_port):raise AssertionError('unexpected_fixture_destination')
        return socket.create_connection(('127.0.0.1',server.server_address[1]),timeout=min(timeout,3))
    return dial


class IMAPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        selected=None
        self.wfile.write(b'* OK synthetic IMAP ready\r\n')
        while line:=self.rfile.readline(8192):
            words=line.rstrip(b'\r\n').split();tag,command=words[:2];command=command.upper()
            self.server.events.append({'command':command.decode('ascii'),'tls':isinstance(self.connection,ssl.SSLSocket)})
            if command==b'UID':self.server.events.append({'command':'UID_'+words[2].decode('ascii').upper(),'tls':isinstance(self.connection,ssl.SSLSocket)})
            if command==b'CAPABILITY':self.wfile.write(b'* CAPABILITY IMAP4rev1 UIDPLUS '+self.server.move_capability+b'\r\n')
            elif command==b'LOGIN':
                expected=self.server.expected_pair
                matches=expected is None or tuple(word.strip(b'"').decode('ascii') for word in words[2:4])==expected
                self.server.events.append({'authentication_matches':matches,'tls':isinstance(self.connection,ssl.SSLSocket)})
                if not matches:self.wfile.write(tag+b' NO wrong synthetic account\r\n');continue
            elif command==b'LIST':self.wfile.write(b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n* LIST (\\Trash) "/" "Trash"\r\n')
            elif command in (b'EXAMINE',b'SELECT') and words[2].strip(b'"') in (b'INBOX',b'Trash'):
                selected=words[2].strip(b'"');validity=b'111' if selected==b'INBOX' else b'333'
                self.wfile.write(b'* 1 EXISTS\r\n* OK [UIDVALIDITY '+validity+b'] fixture\r\n* OK [UIDNEXT 8] fixture\r\n')
            elif command==b'UID' and words[2].upper()==b'SEARCH':self.wfile.write(b'* SEARCH 7\r\n')
            elif command==b'UID' and words[2].upper()==b'FETCH':
                if words[4:]==[b'(UID',b'FLAGS)']:
                    if not self.server.moves:self.wfile.write(b'* 1 FETCH (UID 7 FLAGS ())\r\n')
                    self.wfile.write(tag+b' OK metadata\r\n');continue
                raw=b'From: sender@example.invalid\r\nTo: owner@example.invalid\r\nSubject: Synthetic fixture\r\nDate: Sat, 10 Oct 2026 12:00:00 +0000\r\n\r\nSynthetic body only.'
                self.wfile.write(b'* 1 FETCH (UID 7 FLAGS () RFC822.SIZE '+str(len(raw)).encode()+b' BODY[] {'+str(len(raw)).encode()+b'}\r\n'+raw+b')\r\n')
            elif (command==b'UID' and words[2].upper()==b'MOVE' and len(words)==5 and words[3]==b'7'
                  and words[4]==b'"Trash"' and selected==b'INBOX' and self.server.move_capability==b'MOVE' and not self.server.moves):
                self.server.moves.append({'source_uid':7,'target_uid':77,'target_uidvalidity':333})
                self.wfile.write(b'* OK [COPYUID 333 7 77] fixture\r\n* 1 EXPUNGE\r\n')
            elif command==b'LOGOUT':self.wfile.write(b'* BYE fixture\r\n'+tag+b' OK logout\r\n');break
            else:self.wfile.write(tag+b' BAD fixture rejects unsupported command\r\n');continue
            self.wfile.write(tag+b' OK complete\r\n')


class SMTPHandler(socketserver.StreamRequestHandler):
    def finish(self):
        try:super().finish()
        finally:self.connection.close()

    def handle(self):
        self.wfile.write(b'220 synthetic SMTP fixture\r\n')
        while line:=self.rfile.readline(32768):
            command=line.split(b' ',1)[0].strip().upper();encrypted=isinstance(self.connection,ssl.SSLSocket)
            self.server.events.append({'command':command.decode('ascii'),'tls':encrypted})
            if command==b'EHLO':
                self.wfile.write(b'250-fixture\r\n')
                if not encrypted and self.server.support_starttls:self.wfile.write(b'250-STARTTLS\r\n')
                self.wfile.write(b'250 AUTH PLAIN\r\n')
            elif command==b'STARTTLS' and self.server.support_starttls:
                self.wfile.write(b'220 begin TLS\r\n');self.wfile.flush()
                self.rfile.close();self.wfile.close()
                self.connection=self.server.context.wrap_socket(self.connection,server_side=True)
                self.rfile=self.connection.makefile('rb');self.wfile=self.connection.makefile('wb',buffering=0)
            elif command==b'AUTH':
                expected=self.server.expected_pair
                decoded=base64.b64decode(line.strip().split()[-1]).decode('ascii').split('\x00')
                matches=expected is None or tuple(decoded[-2:])==expected
                self.server.events.append({'authentication_matches':matches,'tls':encrypted})
                self.wfile.write(b'235 authenticated\r\n' if encrypted and matches else b'535 denied\r\n')
            elif command in (b'MAIL',b'RCPT',b'RSET'):
                if command==b'MAIL' and hasattr(self.server,'expected_sender'):
                    # SMTP keywords are case-insensitive; mailbox bytes remain exact.
                    prefix,separator,arguments=line.partition(b':')
                    mailbox=arguments.strip().split(maxsplit=1)[0] if separator and arguments.strip() else b''
                    expected=b'<'+self.server.expected_sender.encode('ascii')+b'>'
                    self.server.events.append({'sender_matches':prefix.upper()==b'MAIL FROM' and mailbox==expected})
                self.wfile.write(b'250 accepted\r\n')
            elif command==b'DATA':
                self.wfile.write(b'354 content\r\n')
                while content:=self.rfile.readline(32768):
                    if content==b'.\r\n':break
                self.wfile.write(b'250 fixture accepted\r\n')
            elif command==b'QUIT':self.wfile.write(b'221 bye\r\n');break
            else:self.wfile.write(b'500 unsupported\r\n')


class DAVHandler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*unused):pass
    def reply(self,status,raw=b'',headers=None):
        self.send_response(status)
        self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close')
        for key,val in (headers or {}).items():self.send_header(key,val)
        self.end_headers();self.wfile.write(raw)
    def perform(self):
        content=self.rfile.read(int(self.headers.get('Content-Length','0')))
        if self.server.expected_pair is not None:
            expected='Basic '+base64.b64encode(':'.join(self.server.expected_pair).encode('ascii')).decode('ascii')
            matches=self.headers.get('Authorization')==expected
            self.server.events.append({'authentication_matches':matches,'tls':isinstance(self.connection,ssl.SSLSocket)})
            if not matches:return self.reply(401)
        origin='https://'+self.headers['Host'];url=origin+self.path
        self.server.events.append({'method':self.command,'path':self.path,'tls':isinstance(self.connection,ssl.SSLSocket),'auth_present':bool(self.headers.get('Authorization'))})
        if self.command=='PUT':
            old=self.server.objects.get(self.path)
            if old and self.headers.get('If-Match')!=old[1] or not old and self.headers.get('If-None-Match')!='*':return self.reply(412)
            self.server.objects[self.path]=(content,'"fixture-new"');return self.reply(204 if old else 201,headers={'ETag':'"fixture-new"'})
        if self.command=='GET':
            found=self.server.objects.get(self.path)
            return self.reply(200,found[0],{'ETag':found[1]}) if found else self.reply(404)
        if self.command=='DELETE':
            found=self.server.objects.get(self.path)
            if not found or self.headers.get('If-Match')!=found[1]:return self.reply(412)
            del self.server.objects[self.path];return self.reply(204)
        request=ET.fromstring(content)
        if self.command=='PROPFIND':
            if request.find('.//{'+DAV+'}current-user-principal') is not None:
                result=xml_response(url,[value(DAV,'current-user-principal',child=value(DAV,'href','/principal/'))])
            elif request.find('.//{'+CAL+'}calendar-home-set') is not None:result=xml_response(url,[value(CAL,'calendar-home-set',child=value(DAV,'href','/calendars/'))])
            elif request.find('.//{'+CARD+'}addressbook-home-set') is not None:result=xml_response(url,[value(CARD,'addressbook-home-set',child=value(DAV,'href','/addressbooks/'))])
            elif request.find('.//{'+DAV+'}acl') is not None:
                acl=value(DAV,'acl');ace=ET.SubElement(acl,'{'+DAV+'}ace');principal=ET.SubElement(ace,'{'+DAV+'}principal');prop=ET.SubElement(principal,'{'+DAV+'}property');ET.SubElement(prop,'{'+DAV+'}owner')
                grant=ET.SubElement(ace,'{'+DAV+'}grant');ET.SubElement(ET.SubElement(grant,'{'+DAV+'}privilege'),'{'+DAV+'}write')
                privileges=value(DAV,'current-user-privilege-set',child=value(DAV,'privilege',child=value(DAV,'all')))
                properties=[value(DAV,'owner',child=value(DAV,'href','/principal/'))]
                if self.server.include_acl:properties.append(acl)
                if self.server.privilege_mode!='unknown':properties.append(privileges if self.server.privilege_mode=='allow' else value(DAV,'current-user-privilege-set'))
                result=xml_response(url,properties)
            elif self.path=='/calendars/':result=xml_response(origin+'/calendars/example/',[value(DAV,'displayname','Synthetic calendar'),value(DAV,'resourcetype',child=value(CAL,'calendar'))])
            elif self.path=='/addressbooks/':result=xml_response(origin+'/addressbooks/example/',[value(DAV,'displayname','Synthetic contacts'),value(DAV,'resourcetype',child=value(CARD,'addressbook'))])
            else:
                result=ET.Element('{'+DAV+'}multistatus')
                for path,entry in self.server.objects.items():
                    if path.startswith(self.path):result.extend(xml_response(origin+path,[value(DAV,'getetag',entry[1])]))
        elif request.tag in ('{'+CARD+'}addressbook-query','{'+CARD+'}addressbook-multiget'):
            result=xml_response(origin+'/addressbooks/example/person.vcf',[value(CARD,'address-data',VCARD),value(DAV,'getetag','"fixture"')])
        else:
            result=xml_response(origin+'/calendars/example/event.ics',[value(CAL,'calendar-data',INITIAL.decode()),value(DAV,'getetag','"fixture"')])
        self.reply(207,ET.tostring(result,encoding='utf-8'),{'Content-Type':'application/xml'})
    do_PROPFIND=perform
    do_REPORT=perform
    do_GET=perform
    do_PUT=perform
    do_DELETE=perform
