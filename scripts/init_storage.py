"""Initialize only empty, newly created named volumes; never read account bytes."""
import os
from pathlib import Path
import stat


def initialize(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise RuntimeError('storage_directory_required')
    if info.st_uid == 1000 and info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o700:
        return
    if info.st_uid != 0 or any(path.iterdir()):
        raise RuntimeError('refusing_existing_or_unexpected_storage')
    os.chmod(path, 0o700, follow_symlinks=False)
    os.chown(path, 1000, 1000, follow_symlinks=False)


if __name__ == '__main__':
    for directory in ('/run/identity', '/run/secrets'):
        initialize(directory)
    print('Private named volumes ready for UID 1000; existing files were not read.')
