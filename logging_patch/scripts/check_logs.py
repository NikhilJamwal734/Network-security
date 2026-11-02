"""Show status of structured audit logs; no raw log content is printed."""
from __future__ import annotations
import argparse
from pathlib import Path

names = ['application', 'api_access', 'upload_audit', 'security_analysis', 'error']


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dir', type=Path, default=None, help='Override log folder')
    args = p.parse_args()
    if args.dir is not None:
        folder = args.dir
    else:
        from app.core.audit_logging import log_directory
        folder = log_directory()
    print('Log directory:', folder)
    for name in names:
        file = folder / (name + '.log')
        print(f'{name:20} {file.stat().st_size if file.is_file() else 0:>12} bytes' + ('' if file.is_file() else ' (not created yet)'))


if __name__ == '__main__':
    main()
