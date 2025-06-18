import json
import os
import boto3

DDBTBL_MCP_SERVER_REGISTRY = os.environ.get("DDBTBL_MCP_SERVER_REGISTRY", "")

cors_headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
    'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'
}

def lambda_handler(event, context):
    # Check HTTP method
    http_method = event.get('httpMethod', '')
    
    # Handle OPTIONS request for CORS
    if http_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': ''
        }
    
    # Only process GET requests
    if http_method != 'GET':
        return {
            'statusCode': 405,
            'headers': cors_headers,
            'body': json.dumps({'error': 'Method not allowed. Only GET requests are supported.'})
        }
    
    # Get the action parameter from query string parameters
    query_params = event.get('queryStringParameters', {}) or {}
    action = query_params.get('action', '')
    
    # Check if action is 'discovery'
    if action == 'discovery':
        return get_server_registry()
    else:
        # Return invalid action message
        return {
            'statusCode': 400,
            'headers': cors_headers,
            'body': json.dumps({'error': 'Invalid action. Supported actions: discovery'})
        }

def get_server_registry():
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(DDBTBL_MCP_SERVER_REGISTRY)
    
    try:
        # Scan the table to get all items
        response = table.scan()
        items = response.get('Items', [])
        
        # Format the items to include only id, description, server
        formatted_items = []
        for item in items:
            formatted_item = {
                'id': item.get('id', ''),
                'description': item.get('description', ''),
                'server': item.get('server', '')
            }
            formatted_items.append(formatted_item)
        
        # Return the formatted items as JSON
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps(formatted_items)
        }
    except Exception as e:
        # Handle any errors
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'error': str(e)})
        }
