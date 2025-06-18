from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

mcp = FastMCP("server")

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


@mcp.tool()
async def executeTrade(ticker, quantity, price):
    """
    Execute a trade for the given ticker, quantity, and price.
    
    Sample input:
    {
        "ticker": "AMZN",
        "quantity": 1000,
        "price": 150.25
    }

    """
    # Simulate trade execution
    return {
        "tradeId": "T12345",
        "status": "Executed",
        "timestamp": "2025-04-09T22:58:00"
    }
    
@mcp.tool()
async def sendTradeDetails(tradeId):
    """
    Send trade details for the given tradeId.

    Sample input:
    {
        "tradeId": "T12345"
    }
    """
    return {
        "status": "Details Sent",
        "recipientSystem": "MiddleOffice",
        "timestamp": "2025-04-09T22:59:00"
    }

if __name__ == "__main__":
    mcp.run(host="0.0.0.0", transport="streamable-http")
