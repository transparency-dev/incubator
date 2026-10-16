# Woodpecker Web

Woodpecker Web is a static HTML file that can be dropped at the root of a `tlog-tiles` log to provide a web viewer.

![Screenshot of Woodpecker Web](./woodpecker-web.png)

## Overview
Woodpecker Web is based on [Woodpecker](https://github.com/mhutchinson/woodpecker/), which is a CLI log inspector. While Woodpecker is a command-line tool for inspecting logs, Woodpecker Web is designed to be deployed by a log operator. Once deployed at the root of a log, it gives log viewing capabilities to anyone with a web browser. This makes it much easier to share visibility into a log without requiring users to install specialized CLI tools.

Note that this version of Woodpecker Web is designed to view a single log.

> [!WARNING]
> This does not perform any verification, it simply shows the contents of the log.
> This viewer is for convenience only, and should NOT be used in a load-bearing manner.
> Verification can be added in the future, but this only has benefit if the HTML file is verified.

## How it Works
Woodpecker Web fetches the `./checkpoint` file to learn the current size of the log. It then fetches data tiles from the `./tile/entries/...` directory structure. This implementation follows the [tlog-tiles specification](https://c2sp.org/tlog-tiles), which is key to understanding how this tool operates and how the log data is structured.

The tiles are expected to be formatted as a stream of Length-Value Payloads (LVP) with 2-byte big-endian length prefixes.

## Features

### For Users
- **Checkpoint Inspector**: View the raw checkpoint and signatures.
- **Entry Browser**: Lists entries with their index and size.
- **Jump to Index**: Quickly navigate to a specific entry by index.
- **Detail Modal**: Inspect entries in both interpreted (text/JSON) and raw hex formats.
- **Proof Exporter**: Generate and export a `tlog-proof` bundle for any entry, with a copyable verification command for `tlog-verify`.

### For Log Operators
- **Customizable**: Contains a `LOG_CUSTOMIZER` object in the script to allow custom rendering of log entries to fit your specific log schema.

## Offline Proof Verification

While Woodpecker Web is a convenient tool for browsing log entries, it runs in the browser and does not perform cryptographic verification of the log's integrity or the inclusion of entries.

For security-sensitive operations, you can export a `tlog-proof` bundle for any entry and verify it offline.

![Screenshot of Woodpecker Web Proof Export](./woodpecker-web-proof.png)

The export dialog allows you to download both the `tlog-proof` bundle and the raw leaf data file. The proof can then be verified offline using the [tlog-verify](../cmd/tlog-verify) command-line tool. The dialog provides the exact command-line invocation to verify the proof using either the downloaded leaf file (recommended, as it verifies the actual content) or the pre-computed leaf hash.

## Usage
Copy `index.html` to the root of your `tlog-tiles` directory (next to `./checkpoint`, `./tile`, etc.). Customize the leaf renderer if viewing the bytes as a string isn't what you want.
