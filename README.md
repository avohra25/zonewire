# zonewire

A small authoritative DNS toolkit in pure Go (standard library only).

This first cut is the wire-format layer: the `dns` package encodes and
decodes RFC 1035 messages with name compression, case preservation and
strict validation of malformed input. Zone files, an authoritative server and
a query CLI are on the way.

```sh
go test ./...
```

## License

MIT
