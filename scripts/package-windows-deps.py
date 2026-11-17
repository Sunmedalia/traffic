#!/usr/bin/env python3
"""Build the optional, offline Windows x64 plaintext-probe runtime."""
import argparse
import hashlib
import io
from pathlib import Path
import re
import shutil
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = [
    ('https://www.python.org/ftp/python/3.13.11/python-3.13.11-embed-amd64.zip',
     '1ec066fb61ba5e8c73e29e048cd07c26850f74585e3a116005135b31b8004890'),
    ('https://files.pythonhosted.org/packages/57/21/1ea24efe23efac04d25bce7156ddbd2763c8a8e1db516ad10c5c30c045c7/frida-17.5.1-cp37-abi3-win_amd64.whl',
     '7efdeb7e95c8e025517e203c2d1121c9eb07c9a3f33a1312ed5960c757e2fe98'),
]
HELPERS = ('probe-iis.py', 'probe-iis.js', 'iis-plaintext.js', 'probe-openssl.py',
           'openssl-plaintext.js', 'openssl-profiles.json')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', default='dist')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', args.version):
        parser.error('version must be a v-prefixed semantic version')
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='traffic-windows-deps-') as temporary:
        # Extract alongside traffic.exe; the deps directory is optional.
        package = Path(temporary) / 'deps'
        runtime = package / 'python'
        runtime.mkdir(parents=True)
        sources = []
        for index, (url, digest) in enumerate(DOWNLOADS):
            with urllib.request.urlopen(url, timeout=120) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError('checksum mismatch: ' + url)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                archive.extractall(runtime if index == 0 else runtime / 'Lib/site-packages')
            sources.append(digest + '  ' + url)
        (runtime / 'python313._pth').write_text('python313.zip\n.\nLib/site-packages\nimport site\n', encoding='ascii')
        helpers = package / 'probes'
        helpers.mkdir()
        for name in HELPERS:
            shutil.copy2(ROOT / 'scripts/windows' / name, helpers / name)
        shutil.copy2(ROOT / 'docs/windows-dependencies.md', package / 'README.md')
        shutil.copy2(ROOT / 'THIRD_PARTY_NOTICES.md', package / 'THIRD_PARTY_NOTICES.md')
        (package / 'SOURCES.sha256').write_text('\n'.join(sources) + '\n', encoding='utf-8')
        archive = output / f'traffic-{args.version}-windows-amd64-deps.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
            for file in sorted(package.rglob('*')):
                if file.is_file():
                    bundle.write(file, file.relative_to(package.parent).as_posix())
        print(archive)


if __name__ == '__main__':
    main()
