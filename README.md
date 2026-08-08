# TicketMCP - China Live Events MCP Server

MCP Server for searching concerts, comparing ticket prices across Chinese ticketing platforms.

## Connection

**Protocol:** Streamable HTTP  
**Endpoint:** `https://pianam.cn/mcp`

### MCP Client Configuration
```json
{
  "mcpServers": {
    "ticket-mcp": {
      "url": "https://pianam.cn/mcp"
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
| get_show_details | Single show details with seat maps |
| get_cities | Available cities list |
| get_call_stats | Service call statistics (admin) |

## Tech Stack
- Python 3.12 + FastMCP (Streamable HTTP transport)
- Nginx reverse proxy with SSL
- Backend API on port 3000

## Deployment
See `部署指南.md` for full deployment instructions.

## License
MIT
