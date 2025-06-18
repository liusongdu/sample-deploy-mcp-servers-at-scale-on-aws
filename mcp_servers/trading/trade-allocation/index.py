from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

mcp = FastMCP("server")

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")

@mcp.tool()
async def allocateTrade(tradeId, accounts):
    """
    Allocate a trade to the given accounts.

    Sample input:
    {
        "tradeId": "XXXXXX",
        "accounts": ["A123", "A456"]
    }
    """
    # Simulate trade allocation
    return {
        "status": "Allocated",
        "timestamp": "2025-04-09T22:59:00"
    }
    
@mcp.tool()
async def validateAllocation(tradeId, accounts):
    """
    Validate the allocation of a trade to the given accounts.

    Sample input:
    {
        "tradeId": "XXXXXX",
        "accounts": ["A123", "A456"]
    }
    """
    # Simulate allocation validation
    return {
        "status": "Validated",
        "timestamp": "2025-04-09T22:59:00"
    }

if __name__ == "__main__":
    mcp.run(host="0.0.0.0", transport="streamable-http")
