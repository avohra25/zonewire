# zonewire

A small authoritative DNS toolkit in pure Go (standard library only).

So far it has three layers:

- `dns` encodes and decodes RFC 1035 messages with name compression, case
  preservation and strict validation of malformed input.
- `zone` parses master files (`$ORIGIN`, `$TTL`, parentheses, relative
  names, TTL units, RFC 3597 `\#` syntax) and answers queries the way an
  authoritative server does: CNAME chasing, wildcards, empty non-terminals,
  referrals with glue and negative answers with the SOA.
- `server` serves zones over UDP and TCP (pipelined, RFC 7766) with EDNS0
  payload sizes, TC-bit truncation, FORMERR/NOTIMP/REFUSED handling and AXFR
  zone transfers, plus a client that falls back to TCP on truncation and a
  TTL-aging cache with negative caching and LRU eviction.

A command-line tool is on the way.

```sh
go test ./...
```

## License

MIT
