from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

mcp = FastMCP("server")

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")

@mcp.tool()
async def matchConfirmation(tradeId, counterpartyId):
    """
    Trade confirmation matching with counter party.

    Sample input:
    {
        "tradeId": "T12345",
        "counterpartyId": "CP67890"
    }

    """
    return {
        "confirmationMatched": True,
        "matchDetails": {"counterpartyName": "ABC Corp"},
        "timestamp": "2025-04-10T00:00:00"
    }


@mcp.tool()
async def processSettlement(tradeId):
    """
    Processes the settlement of a trade.

    Sample input:
    {
        "tradeId": "T12345",
        "settlementDate": "2025-04-10"
    }

    """
    return {
        "status": "Settled",
        "settlementId": "SETT-20250410-98765",
        "timestamp": "2025-04-10T00:05:00"
    }


    
if __name__ == "__main__":
    mcp.run(host="0.0.0.0", transport="streamable-http")
