#!/usr/bin/env python3
"""Stage the complete offline Windows capture runtime inside the collector package."""
import argparse
import hashlib
import io
from pathlib import Path
import shutil
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


WINDIVERT = ('https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip',
             '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15')
WINDIVERT_SOURCE = ('https://github.com/basil00/WinDivert/archive/refs/tags/v2.2.2.tar.gz',
                    '300c1b14e08652e0f8647bf06e9b212f924af76cb2459bd0f88da481c9b08336')


def download(url, digest):
    request = urllib.request.Request(url, headers={'User-Agent': 'traffic-release-builder'})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('checksum mismatch: ' + url)
    return data


def stage_dependencies(package):
    runtime = package / 'python'
    runtime.mkdir(parents=True)
    sources = []
    for index, (url, digest) in enumerate(DOWNLOADS):
        data = download(url, digest)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive.extractall(runtime if index == 0 else runtime / 'Lib/site-packages')
        sources.append(digest + '  ' + url)
    (runtime / 'python313._pth').write_text('python313.zip\n.\nLib/site-packages\nimport site\n', encoding='ascii')
    helpers = package / 'probes'
    helpers.mkdir()
    for name in HELPERS:
        shutil.copy2(ROOT / 'scripts/windows' / name, helpers / name)
    driver = package / 'windivert'
    driver.mkdir()
    with zipfile.ZipFile(io.BytesIO(download(*WINDIVERT))) as archive:
        prefix = 'WinDivert-2.2.2-A/'
        for name in ('x64/WinDivert.dll', 'x64/WinDivert64.sys', 'LICENSE', 'README'):
            (driver / Path(name).name).write_bytes(archive.read(prefix + name))
    # Corresponding unmodified driver/library source accompanies the LGPL binary.
    (driver / 'WinDivert-2.2.2-source.tar.gz').write_bytes(download(*WINDIVERT_SOURCE))
    sources.extend(digest + '  ' + url for url, digest in (WINDIVERT, WINDIVERT_SOURCE))
    shutil.copy2(ROOT / 'docs/windows-dependencies.md', package / 'README.md')
    (package / 'SOURCES.sha256').write_text('\n'.join(sources) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='bin/windows-deps')
    args = parser.parse_args()
    stage_dependencies(Path(args.output).resolve())


if __name__ == '__main__':
    main()
