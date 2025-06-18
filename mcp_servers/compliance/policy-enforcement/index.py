from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

mcp = FastMCP("server")

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")

@mcp.tool()
async def auditCompliance(tradeId):
    """
    Audits the compliance of a trade.

    Sample input:
    {
        "tradeId": "T12345"
    }    
    """
    return {
        "auditStatus": "Compliant",
        "violationsFound": 0,
        "timestamp": "2025-04-09T23:45:00"
    }


@mcp.tool()
async def monitorMarketAbuse(tradeId):
    """
    Monitors market abuse for a given trade.

    Sample input:
    {
        "tradeId": "T12345"
    }
    """
    return {
        "abuseDetected": False,
        "rulesChecked": ["InsiderTrading", "Spoofing"],
        "timestamp": "2025-04-09T23:50:00"
    }


@mcp.tool()
async def updateComplianceRules(policyId):
    """
    Updates the compliance rules for a given policy.

    Sample input:
    {
        "policyId": "POLICY001",
        "newRules": [
            {"ruleName": "Anti-Money Laundering", "description": "..."},
            {"ruleName": "Trade Surveillance", "description": "..."}
        ]
    }

    """
    return {
        "updateStatus": "Success",
        "updatedRulesCount": 2,
        "timestamp": "2025-04-09T23:55:00"
    }


    
if __name__ == "__main__":
    mcp.run(host="0.0.0.0", transport="streamable-http")
