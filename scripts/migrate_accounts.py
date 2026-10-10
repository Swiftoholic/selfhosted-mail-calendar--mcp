"""Explicit offline, local-only single-v2 to multi-v3 account import.

Never starts services, opens the identity database, contacts providers or prints
credentials. Existing single-account files remain unchanged. Identity, scopes,
consent revisions/generations and irreversible-operation receipts are untouched.
"""
import argparse
import json
import os
from pathlib import Path


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def main(argv=None):
    try:
        parser = SafeParser()
        parser.add_argument('--accounts-directory', required=True)
        parser.add_argument('--profiles', required=True)
        parser.add_argument('--offline-confirmed', action='store_true')
        args = parser.parse_args(argv)
        if os.name != 'posix' or os.getuid() != 1000 or not args.offline_confirmed:
            raise ValueError('offline_uid1000_required')
        if any(not Path(value).is_absolute() or '..' in Path(value).parts for value in (args.accounts_directory,args.profiles)):
            raise ValueError('absolute_paths_required')
        if not Path(args.profiles).exists():
            raise ValueError('explicit_profiles_file_required')
        os.umask(0o077)
        from bridge.providers import load_profiles
        from mcp_bridge.accounts import AccountSecrets
        from bridge.app import ApiError
        try:
            result = AccountSecrets(args.accounts_directory, profiles=load_profiles(args.profiles)).migrate_single_accounts()
        except ApiError as error:
            print(json.dumps({'status': 'blocked', 'code': error.code}))
            return 2
        print(json.dumps({'status': 'ready', **result}, sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'status': 'blocked', 'code': 'offline_migration_rejected'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
