import json
import os
import boto3

mcp_server_clusters = json.loads(os.environ.get("MCP_SERVER_CLUSTERS", "[]"))
ddbtbl_name = os.environ.get("DDBTBL_NAME", "")

mcp_servers = []
for mcp_server_cluster in mcp_server_clusters:
    vpce_dns = mcp_server_cluster.get("VPCE_DNS", "").split(":")[1]
    for server in mcp_server_cluster.get("MCP_SERVERS", []):
        mcp_servers.append({
            "id": server.get("id", ""),
            "description": server.get("description", ""),
            "server": f"http://{vpce_dns}:{server.get('port', '')}/mcp",
        }) 

def lambda_handler(event, context):
    """
    Lambda handler function to populate DynamoDB table with MCP server information.
    """
    try:
        # Initialize DynamoDB client
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(ddbtbl_name)
        
        # Check if table name is provided
        if not ddbtbl_name:
            return {
                'statusCode': 400,
                'body': json.dumps('DynamoDB table name not provided')
            }
        
        # Write each MCP server to DynamoDB
        with table.batch_writer() as batch:
            for server in mcp_servers:
                batch.put_item(Item=server)
        
        return {
            'statusCode': 200,
            'body': json.dumps(f'Successfully wrote {len(mcp_servers)} MCP servers to DynamoDB table {ddbtbl_name}')
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error writing to DynamoDB: {str(e)}')
        }
