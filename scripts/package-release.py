#!/usr/bin/env python3
"""Package only runtime binaries and required third-party licence notices."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module_notices(destination):
    raw = subprocess.check_output(['go', 'list', '-m', '-json', 'all'], cwd=ROOT, text=True)
    decoder = json.JSONDecoder()
    while raw.strip():
        module, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        if module.get('Main'):
            continue
        directory = Path(module.get('Dir', '/nonexistent'))
        for file in directory.glob('*'):
            if file.is_file() and file.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS')):
                target = destination / module['Path'].replace('/', '_') / file.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=['linux-amd64', 'linux-arm64', 'windows-amd64', 'java'])
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', default='dist')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', args.version):
        parser.error('version must be a v-prefixed semantic version')
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = f'traffic-{args.version}-{args.platform}'
    with tempfile.TemporaryDirectory(prefix='traffic-release-') as temporary:
        package = Path(temporary) / name
        package.mkdir()
        shutil.copy2(ROOT / 'THIRD_PARTY_NOTICES.md', package / 'THIRD_PARTY_NOTICES.txt')
        if args.platform == 'java':
            shutil.copy2(ROOT / 'java-agent/target/traffic-java-agent.jar', package / 'traffic-java-agent.jar')
            with zipfile.ZipFile(package / 'traffic-java-agent.jar') as jar:
                for entry in jar.namelist():
                    if entry.startswith('META-INF/') and not entry.endswith('/') and any(key in entry.upper() for key in ['LICENSE', 'NOTICE']):
                        target = package / 'licenses' / entry
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(jar.read(entry))
        else:
            suffix = '.exe' if args.platform.startswith('windows') else ''
            for binary in ['traffic', 'traffic-tui']:
                shutil.copy2(ROOT / 'bin' / (binary + suffix), package / (binary + suffix))
            module_notices(package / 'licenses')
            if args.platform.startswith('linux'):
                shutil.copy2(ROOT / 'bin/libtraffic-openssl.so', package / 'libtraffic-openssl.so')
        # Consolidate mandatory notices instead of shipping documentation trees.
        notices = package / 'THIRD_PARTY_NOTICES.txt'
        with notices.open('a', encoding='utf-8') as out:
            for file in sorted((package / 'licenses').rglob('*')):
                if file.is_file():
                    out.write('\n\n--- ' + file.relative_to(package / 'licenses').as_posix() + ' ---\n')
                    out.write(file.read_text(encoding='utf-8', errors='replace'))
        shutil.rmtree(package / 'licenses', ignore_errors=True)
        allowed = {'THIRD_PARTY_NOTICES.txt'}
        if args.platform == 'java':
            allowed.add('traffic-java-agent.jar')
        else:
            allowed.update({'traffic' + suffix, 'traffic-tui' + suffix})
            if args.platform.startswith('linux'):
                allowed.add('libtraffic-openssl.so')
        if {p.name for p in package.iterdir()} != allowed:
            raise RuntimeError('unexpected release payload')
        if args.platform.startswith('linux'):
            archive = output / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as bundle:
                bundle.add(package, arcname=name)
        else:
            archive = output / (name + '.zip')
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
                for file in sorted(package.rglob('*')):
                    if file.is_file():
                        bundle.write(file, str(file.relative_to(package.parent)))
        print(archive)


if __name__ == '__main__':
    main()
