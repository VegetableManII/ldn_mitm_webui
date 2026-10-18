# Third-party source

Upstream: https://github.com/dogty/ldn_mitm/tree/beta/bsd-broadcast-relay

Imported from the user-provided ldn_mitm-beta-bsd-broadcast-relay.zip. Archive hash is recorded in upstream-archive.sha256.

Included: tools/relay_server.py and root LICENSE (GPL-2.0).

Local changes to vendor/relay_server.py: main() accepts argv=None; parse_args() receives argv. Packet routing remains unchanged. app.py adds socket instrumentation and optional access filtering without modifying Python's global socket module.
