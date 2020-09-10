"""
Module providing the ASGI app for soter-trivy.
"""

from quart import Quart

from jsonrpc.server import Dispatcher
from jsonrpc.server.adapter.quart import websocket_blueprint


dispatcher = Dispatcher()
# Add the RPC methods for calling out to the Trivy CLI
from . import rpc
dispatcher.register_all(rpc, prefix = 'trivy')


# Build the Quart app
app = Quart(__name__)
# Register the JSON-RPC blueprint
app.register_blueprint(websocket_blueprint(dispatcher), url_prefix = '/')
