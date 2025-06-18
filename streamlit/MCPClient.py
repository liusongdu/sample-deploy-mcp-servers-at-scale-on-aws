import asyncio
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession

class MCPClient():
    
    def __init__(self, name, url):
        self.name = name
        self.url = url
        self.tools = asyncio.run(self._list_tools(name, url))
        
    async def _list_tools(self, mcp_server_name, url):
        async with streamablehttp_client(url) as (read, write, get_session_id):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return {
                    "actionGroupName": mcp_server_name,
                    "actionGroupExecutor": {"customControl": "RETURN_CONTROL"},
                    "functionSchema": {
                        "functions": [
                            {
                                "name": tool.name,
                                "description": tool.description,
                                "parameters": {
                                    key: {
                                        "type": tool.inputSchema["properties"][key]["type"] if "type" in tool.inputSchema["properties"][key] else "string",
                                        "required": True if key in tool.inputSchema["required"] else False
                                    }
                                    for key in tool.inputSchema["properties"].keys()                                
                                },
                            }
                            for tool in tools.tools
                        ]
                    }
                }
                
    def list_tools(self):
        return self.tools
    
    async def _call_tool(self, tool_name, tool_input):
        async with streamablehttp_client(self.url) as (read, write, get_session_id):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, tool_input)
                return result
            
    def call_tool(self, tool_name, tool_input):
        return asyncio.run(self._call_tool(tool_name, tool_input))
    
    