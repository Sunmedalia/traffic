#!/usr/bin/env python3
"""Build separate, self-contained collector and console release archives."""
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
                # Module-cache licences may be read-only on Windows. Do not
                # preserve that attribute in the disposable staging directory.
                shutil.copyfile(file, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=['ubuntu-amd64', 'ubuntu-arm64', 'centos7-amd64', 'centos7-arm64', 'windows-amd64'])
    parser.add_argument('--version', required=True)
    parser.add_argument('--component', required=True, choices=['traffic', 'traffic-console'])
    parser.add_argument('--output', default='dist')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', args.version):
        parser.error('version must be a v-prefixed semantic version')
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = f'{args.component}-{args.version}-{args.platform}'
    with tempfile.TemporaryDirectory(prefix='traffic-release-') as temporary:
        package = Path(temporary) / name
        package.mkdir()
        shutil.copy2(ROOT / 'THIRD_PARTY_NOTICES.md', package / 'THIRD_PARTY_NOTICES.txt')
        suffix = '.exe' if args.platform.startswith('windows') else ''
        shutil.copy2(ROOT / 'bin' / (args.component + suffix), package / (args.component + suffix))
        module_notices(package / 'licenses')
        if args.component == 'traffic':
            deps = package / 'deps'
            deps.mkdir()
            if args.platform.startswith('windows'):
                shutil.copytree(ROOT / 'bin/windows-deps', deps, dirs_exist_ok=True)
            else:
                shutil.copy2(ROOT / 'bin/libtraffic-openssl.so', package / 'libtraffic-openssl.so')
                probe = deps / 'ecapture'
                probe.mkdir()
                for name in ('ecapture', 'ecapture.traffic.json', 'ecapture.LICENSE', 'ecapture-source.tar.gz', 'libpcap.LICENSE'):
                    shutil.copy2(ROOT / 'bin' / name, probe / name)
            java = deps / 'java'
            java.mkdir()
            shutil.copy2(ROOT / 'java-agent/target/traffic-java-agent.jar', java / 'traffic-java-agent.jar')
        (package / 'START.txt').write_text(
            'traffic capture / doctor: --cn-help for Chinese help and examples.\n'
            'traffic-console replaces traffic-tui. Each component is distributed separately.\n'
            'Keep the complete extracted directory; dependencies resolve next to the executable.\n'
            'Windows capture requires an administrator terminal; Linux capture requires root.\n'
            'Ubuntu: Linux kernel >= 3.2. CentOS: CentOS 7+ (glibc >= 2.17 for preload).\n'
            'TLS support also depends on target/kernel capabilities; run traffic doctor first.\n', encoding='utf-8')
        # Consolidate mandatory notices instead of shipping documentation trees.
        notices = package / 'THIRD_PARTY_NOTICES.txt'
        with notices.open('a', encoding='utf-8') as out:
            for file in sorted((package / 'licenses').rglob('*')):
                if file.is_file():
                    out.write('\n\n--- ' + file.relative_to(package / 'licenses').as_posix() + ' ---\n')
                    out.write(file.read_text(encoding='utf-8', errors='replace'))
        shutil.rmtree(package / 'licenses', ignore_errors=True)
        if not args.platform.startswith('windows'):
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
