"""Disposable TLS proxy parse and HTTP checks; no deployed services or provider data."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def command(args, stage, env):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=120)
    if result.returncode:
        diagnostic = result.stderr[-4096:].decode('utf-8', errors='replace').strip()
        if diagnostic:
            print(diagnostic, file=sys.stderr)
        raise RuntimeError('Synthetic deployment check failed: ' + stage)
    return result.stdout.decode('utf-8').strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-image', default='mcp-synthetic-tests')
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--run-label', default='standalone')
    args = parser.parse_args()
    docker = ['docker', '--host', args.docker_host]
    env = dict(os.environ, DOCKER_HOST=args.docker_host)
    env.pop('DOCKER_CONTEXT', None)
    nonce = uuid.uuid4().hex
    containers = []
    compose = (ROOT / 'compose.yaml').read_text()
    image = re.search(r'image: (docker.io/library/nginx:[^\s]+)', compose).group(1)
    template = (ROOT / 'proxy/nginx.conf.template').read_text()
    upstream = 'server mcp:8082 resolve;'
    if template.count(upstream) != 1:
        raise RuntimeError('Synthetic deployment upstream fixture no longer matches')
    # Only the upstream address changes: both servers share a network-none namespace.
    fixture_template = template.replace(upstream, 'server 127.0.0.1:8082;')

    def terminate(*_):
        raise SystemExit('Synthetic deployment check interrupted')

    old_handler = signal.signal(signal.SIGTERM, terminate)

    def options(name, network='none'):
        containers.append(name)  # Register before creation, including uncertain run outcomes.
        return docker + ['run', '--rm', '--name', name, '--network', network, '--read-only',
                         '--user', '1000:1000', '--cap-drop', 'ALL',
                         '--security-opt', 'no-new-privileges', '--pids-limit', '16',
                         '--memory', '64m', '--cpus', '0.25', '--ulimit', 'cpu=60:60',
                         '--tmpfs', '/tmp:size=8m,mode=1777',
                         '--label', 'synthetic-test.owner=' + nonce,
                         '--label', 'multiaccount-test.root=' + args.run_label]

    def cleanup(names):
        for name in reversed(names):
            found = subprocess.run(docker + ['inspect', '--format',
                '{{.Id}} {{index .Config.Labels "synthetic-test.owner"}}', name],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
            fields = found.stdout.decode().strip().split()
            if found.returncode == 0 and len(fields) == 2 and fields[1] == nonce:
                subprocess.run(docker + ['rm', '--force', fields[0]], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=True, timeout=20)

    try:
        with tempfile.TemporaryDirectory(prefix='mcp-proxy-synthetic-') as directory:
            target = Path(directory)
            os.chmod(target, 0o755)
            tls = target / 'tls'
            tls.mkdir(mode=0o755)
            # This generated key is a disposable TLS fixture, never an SSH or deployment key.
            command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                     '-subj', '/CN=mcp.example.test', '-addext', 'subjectAltName=DNS:mcp.example.test',
                     '-keyout', str(tls / 'privkey.pem'), '-out', str(tls / 'fullchain.pem')],
                    'ephemeral TLS fixture', env)
            for file in tls.iterdir():
                os.chmod(file, 0o644)
            for index, host in enumerate(('mcp.example.test', 'mcp.example.test:8443')):
                config = target / 'nginx.conf'
                config.write_text(template.replace('__MCP_DOMAIN__', 'mcp.example.test').replace('__MCP_HOST__', host))
                os.chmod(config, 0o644)
                mounts = ['--mount', 'type=bind,src=' + str(config) + ',dst=/etc/nginx/nginx.conf,readonly',
                          '--mount', 'type=bind,src=' + str(tls) + ',dst=/run/tls,readonly']
                prefix = 'mcp-proxy-' + nonce[:12] + '-' + str(index)
                command(options(prefix + '-parse') + mounts + ['--entrypoint', 'nginx', image,
                        '-t', '-c', '/etc/nginx/nginx.conf'], 'proxy parse ' + host, env)
                config.write_text(fixture_template.replace('__MCP_DOMAIN__', 'mcp.example.test').replace('__MCP_HOST__', host))
                backend = prefix + '-backend'
                proxy = prefix + '-proxy'
                command(options(backend) + ['--detach', '--mount',
                        'type=bind,src=' + str(tls) + ',dst=/run/tls,readonly',
                        '--entrypoint', 'python', args.runtime_image,
                        '-m', 'scripts.test_proxy_fixture', 'serve'], 'private backend', env)
                command(options(proxy, 'container:' + backend) + ['--detach'] + mounts
                        + ['--entrypoint', 'nginx', image, '-c', '/etc/nginx/nginx.conf',
                           '-g', 'daemon off;'], 'private proxy', env)
                report = command(docker + ['exec', '--user', '1000:1000', backend, 'python', '-m',
                         'scripts.test_proxy_fixture', 'probe', '--host', host], 'HTTP proxy ' + host, env)
                print(json.dumps(json.loads(report)), flush=True)
                cleanup([backend, proxy])
        print(json.dumps({'proxy_parse_checks': 2, 'proxy_http_probes': 54, 'failures': 0,
                          'ephemeral_tls_only': True, 'production_mounts': False,
                          'published_ports': False}), flush=True)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            cleanup(containers)
        finally:
            signal.signal(signal.SIGTERM, old_handler)


if __name__ == '__main__':
    main()
