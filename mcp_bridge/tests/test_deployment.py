import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.init_storage import initialize
from scripts.render_proxy import render


class DeploymentTests(unittest.TestCase):
    def test_private_initialized_volume_is_not_changed(self):
        info = SimpleNamespace(st_mode=0o40700, st_uid=1000, st_gid=1000)
        with patch.object(Path, 'lstat', return_value=info), patch.object(Path, 'is_symlink', return_value=False), patch('scripts.init_storage.os.chown') as chown, patch('scripts.init_storage.os.chmod') as chmod:
            initialize('/run/secrets')
            chown.assert_not_called()
            chmod.assert_not_called()

    def test_empty_root_volume_is_initialized_without_reading_files(self):
        info = SimpleNamespace(st_mode=0o40755, st_uid=0, st_gid=0)
        with patch.object(Path, 'lstat', return_value=info), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'iterdir', return_value=iter(())), patch('scripts.init_storage.os.chown') as chown, patch('scripts.init_storage.os.chmod') as chmod:
            initialize('/run/secrets')
            chmod.assert_called_once_with(Path('/run/secrets'), 0o700, follow_symlinks=False)
            chown.assert_called_once_with(Path('/run/secrets'), 1000, 1000, follow_symlinks=False)

    def test_existing_root_volume_and_unexpected_owner_rejected(self):
        for uid, children in ((0, ['existing']), (1001, []), (1000, [])):
            info = SimpleNamespace(st_mode=0o40755, st_uid=uid, st_gid=uid)
            with patch.object(Path, 'lstat', return_value=info), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'iterdir', return_value=iter(children)), patch('scripts.init_storage.os.chown') as chown:
                with self.assertRaises(RuntimeError): initialize('/run/secrets')
                chown.assert_not_called()

    def test_symlink_and_regular_file_rejected(self):
        for mode, link in ((0o100600, False), (0o40700, True)):
            info = SimpleNamespace(st_mode=mode, st_uid=1000, st_gid=1000)
            with patch.object(Path, 'lstat', return_value=info), patch.object(Path, 'is_symlink', return_value=link):
                with self.assertRaises(RuntimeError): initialize('/run/identity')

    def test_proxy_substitutions_require_exact_reviewed_template(self):
        with self.assertRaises(RuntimeError): render('__MCP_HOST__')
        value = render('__MCP_DOMAIN__ __MCP_HOST__ __MCP_HOST__')
        self.assertNotIn('__MCP_', value)
        self.assertIn('mcp.example.test', value)
