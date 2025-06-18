from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

mcp = FastMCP("server")

@mcp.custom_route("/", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")

@mcp.tool()
async def calculateMarketRisk(tradeId):
    """
    Calculates the market risk for a given trade.

    Sample input:
    {
        "tradeId": "T12345"
    }
    """
    return {
        "marketRiskValue": 0.025,
        "riskUnit": "%",
        "timestamp": "2025-04-09T23:05:00"
    }

@mcp.tool()
async def performStressTest(portfolioId):
    """
    Performs a stress test on the given portfolio.

    Sample input:
    {
        "portfolioId": "P98765",
        "scenarios": ["MarketCrash", "InterestRateSpike"]
    }

    """
    return {
        "stressTestResults": [
            {"scenario": "MarketCrash", "impactValue": -250000},
            {"scenario": "InterestRateSpike", "impactValue": -150000}
        ],
        "timestamp": "2025-04-09T23:10:00"
    }

@mcp.tool()
async def evaluateLiquidityRisk(tradeId):
    """
    Evaluates the liquidity risk for a given trade.

    Sample input:
    {
        "tradeId": "T12345"
    }
    """
    return {
        "liquidityRiskScore": 0.85,
        "riskLevel": "High",
        "timestamp": "2025-04-09T23:15:00"
    }

    
if __name__ == "__main__":
    mcp.run(host="0.0.0.0", transport="streamable-http")
