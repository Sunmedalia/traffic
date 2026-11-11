# Third-party components

The eCapture patch applies to upstream commit `143e771cf2b4919aedc27fd7b4b24ff87b8725b9` (v2.9.1), copyright the eCapture authors, licensed under Apache-2.0. Existing copyright and license headers are retained. Changes cover connection-cache safety, inline socket metadata, stream identity, decoder copying, publisher behavior, and regression tests. The build script copies the upstream license alongside the generated executable.

- eCapture source and license — https://github.com/gojue/ecapture/tree/v2.9.1
- Apache-2.0 license — https://github.com/gojue/ecapture/blob/v2.9.1/LICENSE

Go dependencies are referenced through modules, with exact versions and checksums in `go.mod` and `go.sum`. Their respective licenses apply. libpcap is installed and linked through the host environment. No upstream eCapture binary, packet captures, session database, server credentials, or TLS private key is committed to this repository.
