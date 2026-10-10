"""Render a fixed proxy template using validated public configuration only."""
import argparse
import os
from pathlib import Path
from mcp_bridge.config import DOMAIN, HOST


def render(template):
    if template.count('__MCP_DOMAIN__') != 1 or template.count('__MCP_HOST__') != 2:
        raise RuntimeError('unexpected_proxy_template')
    return template.replace('__MCP_DOMAIN__', DOMAIN).replace('__MCP_HOST__', HOST)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='runtime/nginx.conf')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise SystemExit('Refusing symlink output')
    text = render((root / 'proxy/nginx.conf.template').read_text())
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(text)
    os.chmod(target, 0o600)
    print('Proxy configuration rendered for the validated public origin.')


if __name__ == '__main__':
    main()
