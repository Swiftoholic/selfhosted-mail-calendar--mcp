"""Bounded build-time installation of the exact public wheel lock."""
import resource
import subprocess
import sys

resource.setrlimit(resource.RLIMIT_AS, (384 * 1024**2, 384 * 1024**2))
resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
subprocess.run([sys.executable, '-m', 'pip', 'install', '--require-hashes',
                '--only-binary=:all:', '--no-cache-dir', '--disable-pip-version-check',
                '--index-url', 'https://pypi.org/simple', '-r', '/app/requirements.lock',
                '--report', '/app/install-report.json'], check=True, timeout=600)
subprocess.run([sys.executable, '-m', 'pip', 'check'], check=True, timeout=30)
