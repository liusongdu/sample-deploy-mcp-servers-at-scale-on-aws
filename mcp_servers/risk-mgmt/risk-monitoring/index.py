from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

mcp = FastMCP("server")

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")

@mcp.tool()
async def monitorRiskLimits(tradeId):
    """
    Monitor the risk limits for a trade.
    
    Sample input:
    {
        "tradeId": "T12345"
    }
    """
    return {
        "limitBreached": False,
        "riskLimitTypeChecked": ["MarketRiskLimit", "CreditRiskLimit"],
        "timestamp": "2025-04-09T23:20:00"
    }

    
@mcp.tool()
async def generateRiskReport(portfolioId):
    """
    Generates a risk report for a given portfolio.

    Sample input:
    {
        "portfolioId": "P98765"
    }
    """
    return {
        "reportFilePath": "/reports/risk/P98765.pdf",
        "status": "Generated",
        "timestamp": "2025-04-09T23:25:00"
    }

@mcp.tool()
async def flagRiskBreaches(tradeId):
    """
    Flags any risk breaches for a given trade.

    Sample input:
    {
        "tradeId": "T12345"
    }
    """
    return {
        "breachFlagged": True,
        "breachType": "CreditRiskLimitExceeded",
        "timestamp": "2025-04-09T23:30:00"
    }



if __name__ == "__main__":
    mcp.run(host="0.0.0.0", transport="streamable-http")
