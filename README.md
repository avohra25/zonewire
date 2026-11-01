# zonewire

A small authoritative DNS toolkit in pure Go (standard library only).

So far it has two layers:

- `dns` encodes and decodes RFC 1035 messages with name compression, case
  preservation and strict validation of malformed input.
- `zone` parses master files (`$ORIGIN`, `$TTL`, parentheses, relative
  names, TTL units, RFC 3597 `\#` syntax) and answers queries the way an
  authoritative server does: CNAME chasing, wildcards, empty non-terminals,
  referrals with glue and negative answers with the SOA.

A UDP/TCP server and a query CLI are on the way.

```sh
go test ./...
```

## License

MIT
