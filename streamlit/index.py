import streamlit as st
import os
import json

from InlineAgent import InlineAgent
from MCPClient import MCPClient
import random
import boto3
import pandas as pd
import requests
        
st.set_page_config(layout="wide")
st.title("Accelerating AI Innovation: Scaling Model Context Protocol Servers for Enterprise Workloads on AWS")

# Inject custom CSS to increase tab name font size
st.markdown("""
    <style>
    .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
        font-size: 2rem;
    }
    </style>
    """, unsafe_allow_html=True)

# ██       ██████   █████  ██████      ██████  ███████ ███████  ██████  ██    ██ ██████   ██████ ███████ ███████ 
# ██      ██    ██ ██   ██ ██   ██     ██   ██ ██      ██      ██    ██ ██    ██ ██   ██ ██      ██      ██      
# ██      ██    ██ ███████ ██   ██     ██████  █████   ███████ ██    ██ ██    ██ ██████  ██      █████   ███████ 
# ██      ██    ██ ██   ██ ██   ██     ██   ██ ██           ██ ██    ██ ██    ██ ██   ██ ██      ██           ██ 
# ███████  ██████  ██   ██ ██████      ██   ██ ███████ ███████  ██████   ██████  ██   ██  ██████ ███████ ███████ 
registry_api_endpoint = os.environ.get("REGISTRY_API_ENDPOINT", "") + '/registry'
secret_arn = os.environ.get("SECRET_ARN", "")
mcp_servers = json.loads(os.environ.get("MCP_SERVERS", ""))

@st.cache_resource
def initialize_mcp_server_list():
    secretsmanager = boto3.client("secretsmanager")
    response = secretsmanager.get_secret_value(SecretId=secret_arn)
    x_api_key = response['SecretString']
    response = requests.get(registry_api_endpoint, 
        headers={ "x-api-key": x_api_key},
        params={ "action": "discovery" }
    )
    mcp_server_list = json.loads(response.text)
    # prepare the list of mcp server list with MCP Client
    for mcp_server in mcp_server_list:
        mcp_server["client"] = MCPClient(mcp_server.get("id"),mcp_server.get("server"))

    return mcp_server_list

@st.cache_resource
def initialize_agent(_mcp_server_list):
    # prepare the MCP clients that are requied
    mcp_clients = {
        mcp_server.get("id"): mcp_server.get("client") for mcp_server in mcp_server_list if mcp_server.get("id") in mcp_servers
    }
    
    # initialize inline agent
    agent_session_id = str(random.randint(1, 100000))
    
    agent = InlineAgent(
        model_id="us.anthropic.claude-3-5-haiku-20241022-v1:0",
        agent_instruction="""
        You are a AI trading assistant that will help to execute trades and perform post trading processing.
        For each trade you process, you must run it through the functions of the following business divisons:
        - Trading - trading execution / allocation to accounts
        - Operations - post trade settlement
        - Risk Management - management of risk arising from the trade
        - Compliance - compliance to regulations and reporting
        
        All business divisions are required to perform important functions and you are to consider all available functions in your execution.
        """,
        mcp_clients=mcp_clients,
        session_id=agent_session_id
    )

    return agent, agent_session_id, mcp_clients


# ███████ ████████ ██████  ███████  █████  ███    ███ ██      ██ ████████     ██    ██ ██ 
# ██         ██    ██   ██ ██      ██   ██ ████  ████ ██      ██    ██        ██    ██ ██ 
# ███████    ██    ██████  █████   ███████ ██ ████ ██ ██      ██    ██        ██    ██ ██ 
#      ██    ██    ██   ██ ██      ██   ██ ██  ██  ██ ██      ██    ██        ██    ██ ██ 
# ███████    ██    ██   ██ ███████ ██   ██ ██      ██ ███████ ██    ██         ██████  ██ 

def process_input(agent, user_input):
    response, trace = agent.invoke(user_input)
    return response, trace

tab1, tab2 = st.tabs(["MCP Server Registry", "Agentic App"])

with tab1:
    mcp_server_list = initialize_mcp_server_list()
    col_id, col_description = st.columns([1,3])
    with col_id:
        st.subheader("ID")
    with col_description:
        st.subheader("Description")

    for mcp_server in mcp_server_list:
        col_id, col_description = st.columns([1,3])
        
        with col_id:
            st.write(mcp_server.get("id"))
        with col_description:
            st.write(mcp_server.get("description"))
            with st.expander("Expand Tools List"):
                st.write(mcp_server.get("client").list_tools())

agent, agent_session_id, mcp_clients = initialize_agent(mcp_server_list)

with tab2:
    trace = ""
    left, right = st.columns(2)
    with left:
        with st.form(key='input_form'):
            user_input = st.text_area(
                label='How may I help you?', 
                value="Buy 100 shares of AMZN at USD 186 to be distributed equally between accounts A31 and B12.",
            )
            submit_button = st.form_submit_button(label='Submit')
            
    with right:
        if submit_button:
            with st.spinner("Processing trade..."):
                response, trace = process_input(agent, user_input)
            
            st.write(response)
    
    st.divider()
    st.header("Trace")
    st.write(trace)












