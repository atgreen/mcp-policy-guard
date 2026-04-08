#!/bin/bash
# Simple MCP echo server for testing.
# Reads JSON-RPC from stdin, echoes tool call results on stdout.
while IFS= read -r line; do
    # Parse method from JSON
    method=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('method',''))" 2>/dev/null)
    id=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('id')))" 2>/dev/null)

    case "$method" in
        "initialize")
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"echo-server\",\"version\":\"1.0\"}}}"
            ;;
        "tools/list")
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"Echo tool\"},{\"name\":\"database.drop_table\",\"description\":\"Drop a table\"}]}}"
            ;;
        "tools/call")
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}"
            ;;
        *)
            echo "{\"jsonrpc\":\"2.0\",\"id\":${id},\"result\":{}}"
            ;;
    esac
done
