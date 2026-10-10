"""Disposable proxy parse check; no host/provider credentials or deployed services."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, stage):
    result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode:
        raise SystemExit('Synthetic deployment check failed: ' + stage)


def main():
    compose = (ROOT / 'compose.yaml').read_text()
    image = re.search(r'image: (docker.io/library/nginx:[^\s]+)', compose).group(1)
    # This generated key is an ephemeral test fixture, never a real deployment key.
    with tempfile.TemporaryDirectory(prefix='mcp-proxy-synthetic-') as directory:
        target = Path(directory)
        os.chmod(target, 0o755)
        tls = target / 'tls'
        tls.mkdir(mode=0o755)
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=mcp.example.test', '-addext', 'subjectAltName=DNS:mcp.example.test',
             '-keyout', str(tls / 'privkey.pem'), '-out', str(tls / 'fullchain.pem')], 'ephemeral TLS fixture')
        for file in tls.iterdir():
            os.chmod(file, 0o644)
        template = (ROOT / 'proxy/nginx.conf.template').read_text()
        for host in ('mcp.example.test', 'mcp.example.test:8443'):
            config = target / 'nginx.conf'
            config.write_text(template.replace('__MCP_DOMAIN__', 'mcp.example.test').replace('__MCP_HOST__', host))
            os.chmod(config, 0o644)
            run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--user', '1000:1000',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '16',
                 '--memory', '64m', '--tmpfs', '/tmp:size=8m,mode=1777',
                 '--mount', 'type=bind,src='+str(config)+',dst=/etc/nginx/nginx.conf,readonly',
                 '--mount', 'type=bind,src='+str(tls)+',dst=/run/tls,readonly',
                 '--entrypoint', 'nginx', image, '-t', '-c', '/etc/nginx/nginx.conf'], 'proxy '+host)
    print('Synthetic TLS proxy configuration checks passed (default and explicit port).')


if __name__ == '__main__':
    main()
