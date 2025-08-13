# Splunk CLI

CLI that lets you run searches via Splunk's REST API.

## Quickstart

Build

```console
make build
```

Then run a search

```console
./bin/splunk-cli search index=main error --earliest=-24h@h --latest=now
./bin/splunk-cli --splunk-url https://localhost:8089 --splunk-username admin --splunk-password changeme search index=main error
```

## Config

Root flags (highest precedence):

- --splunk-url, --splunk-host, --splunk-port, --splunk-scheme
- --splunk-username, --splunk-password, --splunk-token
- --splunk-insecure, --splunk-timeout

Environment variables (used when flags are not provided):

- SPLUNK_URL (or SPLUNK_HOST/SPLUNK_PORT/SPLUNK_SCHEME)
- SPLUNK_USERNAME, SPLUNK_PASSWORD
- SPLUNK_TOKEN
- SPLUNK_INSECURE (true/1 to skip TLS verify)
- SPLUNK_TIMEOUT_SECONDS (default 60)

## MCP server

An MCP server is available that currently exposes a single tool: `search`.
Start the server via the `mcp` subcommand. Transport options are:

- stdio
- streamable (HTTP)
- sse (Server-Sent Events)

Examples:

```console
# stdio transport
./bin/splunk-cli mcp --mcp-server stdio

# streamable HTTP (listens on :8080)
./bin/splunk-cli mcp --mcp-server streamable

# SSE (listens on :8080)
./bin/splunk-cli mcp --mcp-server sse
```

### MCP server in Cursor

Create a `.cursor/mcp.json` file in your workspace with:

```json
{
    "servers": {
        "splunk": {
            "command": "<full-path>/splunk-cli mcp --mcp-server stdio",
            "env": {
                "SPLUNK_URL": "https://localhost:8089",
                "SPLUNK_USERNAME": "admin",
                "SPLUNK_PASSWORD": "changeme",
                "SPLUNK_INSECURE": "true",
                "SPLUNK_TIMEOUT_SECONDS": "60"
            }
        }
    }
}
```

_(replacing `<full-path>/splunk-cli` by the full path to the `splunk-cli`)_.

## Endpoints used

- `/services/auth/login` (POST) XML sessionKey
- `/services/search/jobs` (POST) JSON/XML sid
- `/services/search/jobs/{sid}` (GET) JSON entry[].content.isDone
- `/services/search/jobs/{sid}/results` (GET) JSON fields/results
