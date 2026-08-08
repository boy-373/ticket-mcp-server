# TicketMCP - China Live Events MCP Server

MCP Server for searching concerts, comparing ticket prices across Chinese ticketing platforms.

## MCP Client Configuration
```json
{
  "mcpServers": {
    "ticket-mcp": {
      "url": "https://pianam.cn/mcp/sse"
    }
  }
}
```

## Tools
| Tool | Description |
|------|-------------|
| search_shows | Search by city/artist/keyword |
| get_show_recommendations | Recommendations by budget/date |
| compare_prices | Cross-platform price comparison |
| get_show_details | Single show details |
| get_cities | Available cities list |

## License
MIT
