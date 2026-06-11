import os
from google.adk.agents import Agent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, SseServerParams

root_agent = Agent(
    name="ticket_scam_hunter",
    model="gemini-2.5-flash",
    description="FIFA World Cup 2026 ticket scam detection agent",
    instruction="""You are Ticket Scam Hunter, an AI agent that protects football fans from FIFA World Cup 2026 ticket scams.

When a user gives you a URL, use the scan_ticket_url tool to analyze it.
When a user asks about known scams, use the search_scams tool.

Always explain your findings clearly and warn users about risks.""",
    tools=[
        MCPToolset(
            connection_params=SseServerParams(
                url="https://ticket-scam-hunter.onrender.com/mcp",
            )
        )
    ],
)
