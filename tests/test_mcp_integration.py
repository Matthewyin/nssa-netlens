import asyncio
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Ensure we can find the pcap file
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP_FILE = os.path.join(PROJECT_ROOT, "tests", "attack_test.pcap")
BACKEND_DIR = os.path.join(PROJECT_ROOT, "python-backend")


async def run():
    print(f"Testing MCP Server in: {BACKEND_DIR}")
    print(f"Target PCAP: {PCAP_FILE}")

    # Check if uv exists
    uv_path = "/Users/matthewyin/.local/bin/uv"
    if not os.path.exists(uv_path):
        print(f"Error: uv not found at {uv_path}")
        return

    server_params = StdioServerParameters(
        command=uv_path,
        args=["run", "pcap-mcp"],
        cwd=BACKEND_DIR,
        env=os.environ.copy(),  # Pass current env
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # 1. List Tools
                print("\n[1] Listing Available Tools...")
                tools_result = await session.list_tools()
                tools = tools_result.tools
                for t in tools:
                    print(f"  - {t.name}: {t.description}")

                if not tools:
                    print("Error: No tools found!")
                    return

                # 2. Call get_pcap_summary
                print(
                    f"\n[2] Calling 'get_pcap_summary' on {os.path.basename(PCAP_FILE)}..."
                )
                result = await session.call_tool(
                    "get_pcap_summary", arguments={"filepath": PCAP_FILE}
                )

                print("Result:")
                for content in result.content:
                    if content.type == "text":
                        # Truncate if too long
                        text = content.text
                        if len(text) > 300:
                            print(text[:300] + "... (truncated)")
                        else:
                            print(text)

                # 3. Call scan_security_threats
                print(f"\n[3] Calling 'scan_security_threats'...")
                result = await session.call_tool(
                    "scan_security_threats", arguments={"filepath": PCAP_FILE}
                )

                print("Result:")
                for content in result.content:
                    if content.type == "text":
                        print(content.text)

                # 4. Call list_tcp_sessions
                print(f"\n[4] Calling 'list_tcp_sessions'...")
                result = await session.call_tool(
                    "list_tcp_sessions", arguments={"filepath": PCAP_FILE}
                )

                print("Result:")
                for content in result.content:
                    if content.type == "text":
                        # Truncate output for readability
                        text = content.text
                        if len(text) > 500:
                            print(text[:500] + "... (truncated)")
                        else:
                            print(text)

        print("\n✅ MCP Server Integration Test Passed!")

    except Exception as e:
        print(f"\n❌ Test Failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run())
