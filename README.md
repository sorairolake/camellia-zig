<!--
SPDX-FileCopyrightText: 2024 Shun Sakai

SPDX-License-Identifier: CC-BY-4.0
-->

# camellia-zig

[![CI][ci-badge]][ci-url]

**camellia-zig** is an implementation of the [Camellia] block cipher written in
pure [Zig].

## Usage

Add this package to your `build.zig.zon`:

```sh
zig fetch --save git+https://github.com/sorairolake/camellia-zig.git
```

Add the following to your `build.zig`:

```zig
const camellia = b.dependency("camellia", .{});
exe.root_module.addImport("camellia", camellia.module("camellia"));
```

### Documentation

See the [documentation][docs-url] for more details.

## Zig version

This library is compatible with Zig version 0.14.0.

## Source code

The upstream repository is available at
<https://github.com/sorairolake/camellia-zig.git>.

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## License

Copyright (C) 2024 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.3 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/camellia-zig/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/camellia-zig/actions?query=branch%3Adevelop+workflow%3ACI++
[Camellia]: https://info.isl.ntt.co.jp/crypt/eng/camellia/
[Zig]: https://ziglang.org/
[docs-url]: https://sorairolake.github.io/camellia-zig/
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: CONTRIBUTING.adoc
[AUTHORS.adoc]: AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec-3.3/
