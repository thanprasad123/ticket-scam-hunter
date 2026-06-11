from fastmcp import FastMCP
import httpx

mcp = FastMCP("ticket-scam-hunter")

@mcp.tool()
async def scan_ticket_url(url: str) -> dict:
    """Analyze a ticket website URL for FIFA World Cup 2026 scam signals"""
    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(
            "https://ticket-scam-hunter.onrender.com/v1/scans",
            json={"url": url}
        )
        return response.json()

@mcp.tool()
async def search_scams(verdict: str = None) -> dict:
    """Search previously detected scam sites in Elasticsearch"""
    async with httpx.AsyncClient(timeout=30) as client:
        params = {}
        if verdict:
            params["verdict"] = verdict
        response = await client.get(
            "https://ticket-scam-hunter.onrender.com/v1/scans",
            params=params
        )
        return response.json()

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8001, path="/mcp")
