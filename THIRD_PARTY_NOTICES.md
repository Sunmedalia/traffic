# Third-party components

The eCapture patch applies to upstream commit `143e771cf2b4919aedc27fd7b4b24ff87b8725b9` (v2.9.1), copyright the eCapture authors, licensed under Apache-2.0. Existing copyright and license headers are retained. Changes cover connection-cache safety, inline socket metadata, stream identity, decoder copying, publisher behavior, and regression tests. The build script copies the upstream license alongside the generated executable.

- eCapture source and license — https://github.com/gojue/ecapture/tree/v2.9.1
- Apache-2.0 license — https://github.com/gojue/ecapture/blob/v2.9.1/LICENSE

Go dependencies are referenced through modules, with exact versions and checksums in `go.mod` and `go.sum`. Their respective licenses apply. The `traffic` collector links libpcap through the host environment. The independent `traffic-tui` analyst reads PCAP using gopacket/pcapgo and does not link libpcap. No upstream eCapture binary, packet captures, session database, server credentials, or TLS private key is committed to this repository.

The interactive terminal interface uses Charm libraries under the MIT license. Exact module versions, including transitive terminal dependencies, are recorded in `go.mod` and `go.sum`.

- Bubble Tea — https://github.com/charmbracelet/bubbletea/blob/main/LICENSE
- Bubbles — https://github.com/charmbracelet/bubbles/blob/main/LICENSE
- Lip Gloss — https://github.com/charmbracelet/lipgloss/blob/main/LICENSE
- Charm terminal utilities — https://github.com/charmbracelet/x

The optional Windows IIS and OpenSSL helpers runs Frida 17.5.1 as a separately installed Python dependency. Frida Core uses the wxWindows Library Licence 3.1, with its additional-use exception. Npcap is installed separately and its vendor licence applies. Neither component is bundled into the Go executable.

- Frida Core licence — https://github.com/frida/frida-core/blob/17.5.1/COPYING
- Frida Python source — https://github.com/frida/frida-python/tree/17.5.1
- Npcap licence — https://npcap.com/npcap-license.html
