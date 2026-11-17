#!/usr/bin/env python3
"""Package CI-built executables, docs, dependency notices, and build metadata."""
import argparse
import hashlib
import json
import os
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
    modules = []
    while raw.strip():
        module, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        if module.get('Main'):
            continue
        modules.append({'path': module['Path'], 'version': module.get('Version', '')})
        directory = Path(module.get('Dir', '/nonexistent'))
        for file in directory.glob('*'):
            if file.is_file() and file.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS')):
                target = destination / module['Path'].replace('/', '_') / file.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file, target)
    return modules


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
        for file in ['README.md', 'OPTIMIZATION.md', 'VALIDATION.md', 'THIRD_PARTY_NOTICES.md']:
            shutil.copy2(ROOT / file, package / file)
        shutil.copytree(ROOT / 'docs', package / 'docs')
        modules = []
        if args.platform == 'java':
            shutil.copy2(ROOT / 'java-agent/target/traffic-java-agent.jar', package / 'traffic-java-agent.jar')
            with zipfile.ZipFile(package / 'traffic-java-agent.jar') as jar:
                for entry in jar.namelist():
                    if entry.startswith('META-INF/') and not entry.endswith('/') and any(key in entry.upper() for key in ['LICENSE', 'NOTICE']):
                        target = package / 'licenses' / entry
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(jar.read(entry))
            runtime = 'JDK 17 or 21; supported Tomcat NIO targets only'
        else:
            (package / 'bin').mkdir()
            suffix = '.exe' if args.platform.startswith('windows') else ''
            for binary in ['traffic', 'traffic-tui']:
                shutil.copy2(ROOT / 'bin' / (binary + suffix), package / 'bin' / (binary + suffix))
            modules = module_notices(package / 'licenses')
            if args.platform.startswith('linux'):
                shutil.copy2(ROOT / 'bin/libtraffic-openssl.so', package / 'bin/libtraffic-openssl.so')
                (package / 'scripts').mkdir()
                shutil.copy2(ROOT / 'scripts/build-ecapture.sh', package / 'scripts/build-ecapture.sh')
                shutil.copytree(ROOT / 'patches', package / 'patches')
                runtime = 'Built on Ubuntu 24.04; glibc 2.39+, libpcap.so.0.8; eCapture installed separately'
            else:
                shutil.copytree(ROOT / 'scripts/windows', package / 'scripts/windows', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
                runtime = 'Windows x64; install Npcap for capture; Python and Frida 17.5.1 for optional plaintext probes'
        metadata = {
            'version': args.version, 'platform': args.platform,
            'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'runtime': runtime, 'go_modules': modules,
            'known_limitations': 'See OPTIMIZATION.md and docs/releases/' + args.version + '.md',
            'bundled_external_probes': False,
        }
        if args.platform != 'java':
            metadata['go'] = subprocess.check_output(['go', 'version'], text=True).strip()
        (package / 'BUILDINFO.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
        files = sorted(p for p in package.rglob('*') if p.is_file())
        (package / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.relative_to(package).as_posix() + '\n' for p in files))
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
