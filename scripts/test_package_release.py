"""Regression checks for split release contents and required offline dependencies."""
import importlib.util
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location('package_release', Path(__file__).with_name('package-release.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PackageReleaseTest(unittest.TestCase):
    def test_linux_package_names_and_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('traffic', 'traffic-console', 'libtraffic-openssl.so', 'ecapture',
                         'ecapture.traffic.json', 'ecapture.LICENSE', 'ecapture-source.tar.gz', 'libpcap.LICENSE'):
                file = root / 'bin' / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'test')
            jar = root / 'java-agent/target/traffic-java-agent.jar'
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b'test')
            (root / 'THIRD_PARTY_NOTICES.md').write_text('test')
            for distro in ('ubuntu', 'centos7'):
                for component in ('traffic', 'traffic-console'):
                    archive_name = f'{component}-v0.1.2-{distro}-amd64'
                    argv = ['package-release.py', '--version', 'v0.1.2', '--platform', distro + '-amd64', '--component', component, '--output', str(root / 'dist')]
                    with patch.object(MODULE, 'ROOT', root), patch.object(MODULE, 'module_notices'), patch.object(sys, 'argv', argv):
                        MODULE.main()
                    with tarfile.open(root / 'dist' / (archive_name + '.tar.gz')) as archive:
                        names = {name.removeprefix(archive_name + '/') for name in archive.getnames()}
                    self.assertIn(component, names)
                    if component == 'traffic':
                        self.assertIn('deps/ecapture/ecapture', names)
                        self.assertIn('deps/java/traffic-java-agent.jar', names)
                        self.assertIn('libtraffic-openssl.so', names)
                    else:
                        self.assertFalse(any(name.startswith('deps/') for name in names))

    def test_windows_components_are_separate_and_collector_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('bin/traffic.exe', 'bin/traffic-console.exe', 'bin/windows-deps/python/python.exe',
                         'bin/windows-deps/windivert/WinDivert.dll', 'bin/windows-deps/windivert/WinDivert64.sys',
                         'bin/windows-deps/probes/probe-iis.py', 'java-agent/target/traffic-java-agent.jar', 'THIRD_PARTY_NOTICES.md'):
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'test')
            for component in ('traffic', 'traffic-console'):
                argv = ['package-release.py', '--version', 'v0.1.2', '--platform', 'windows-amd64', '--component', component, '--output', str(root / 'dist')]
                with patch.object(MODULE, 'ROOT', root), patch.object(MODULE, 'module_notices'), patch.object(sys, 'argv', argv):
                    MODULE.main()
                with zipfile.ZipFile(root / 'dist' / f'{component}-v0.1.2-windows-amd64.zip') as archive:
                    names = {name.split('/', 1)[1] for name in archive.namelist()}
                self.assertIn(component + '.exe', names)
                self.assertNotIn(('traffic-console' if component == 'traffic' else 'traffic') + '.exe', names)
                if component == 'traffic':
                    self.assertIn('deps/windivert/WinDivert64.sys', names)
                    self.assertIn('deps/python/python.exe', names)
                    self.assertIn('deps/probes/probe-iis.py', names)
                    self.assertIn('deps/java/traffic-java-agent.jar', names)
                else:
                    self.assertFalse(any(name.startswith('deps/') for name in names))


if __name__ == '__main__':
    unittest.main()
