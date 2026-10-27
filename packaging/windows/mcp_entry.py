"""PyInstaller entry point for the local MCP server."""

from multiprocessing import freeze_support

from ip_analyser.desktop_mcp import serve_stdio


if __name__ == "__main__":
    freeze_support()
    serve_stdio()
