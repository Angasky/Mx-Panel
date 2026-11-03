# Local YAML emitter patch

Base: `go.yaml.in/yaml/v3 v3.0.6`, copied from the checksum-verified Go module
cache. `UPSTREAM.sha256` records every original file. Original copyright,
`LICENSE`, `NOTICE`, README and upstream tests are retained. The root module
uses an explicit local `replace`; no other dependency is replaced.

Only production change: `yaml_emitter_emit` compacts its event slice after
processing, retaining unconsumed lookahead in order and clearing vacated slots.
Previously, one queue slot remained allocated for every processed event until
the document/stream ended. Parsing, scalar resolution, formatting, validation,
public APIs and persistence policy are unchanged.

`emitter_queue_test.go` reproduces unbounded queue capacity on the unmodified
version and verifies bounded capacity plus multi-document decoding after the
patch. Upstream encode/decode/node/limit tests must also pass.

From the repository root:

```sh
go test ./...
cd third_party/yaml && go test ./...
```

`tools/bench/yaml-compat` emits deterministic hashes for ordinary proxy configs,
large integers, Unicode, multiline secrets, YAML nodes, aliases, custom tags,
comments and multi-document streams at different indentation levels. Compare
the output against the unmodified module before updating this patch.

When upgrading YAML, rebase or remove this patch explicitly, refresh the source
manifest, and rerun the upstream suite, compatibility hashes and HTTP benchmark.
Do not edit the machine-wide module cache.
