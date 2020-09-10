"""
JSON-RPC methods for calling out to the Trivy CLI.
"""

import asyncio
import json
import os
import shlex

from jsonrpc.model import JsonRpcException


TRIVY_COMMAND = os.environ.get('TRIVY_COMMAND', 'trivy')

TRIVY_VERSION_COMMAND = f"{TRIVY_COMMAND} --version --format json"
TRIVY_IMAGE_COMMAND = f"{TRIVY_COMMAND} --quiet image --format json {{image}}"


class TrivyError(JsonRpcException):
    message = "Trivy error"
    code = 100


async def info():
    """
    Returns information about Trivy.
    """
    proc = await asyncio.create_subprocess_shell(
        TRIVY_VERSION_COMMAND,
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE
    )
    stdout_data, stderr_data = await proc.communicate()
    if proc.returncode == 0:
        return json.loads(stdout_data)
    else:
        raise TrivyError(stderr_data)


async def image_scan(image):
    """
    Scans the given image using Trivy and returns vulnerability information.
    """
    command = TRIVY_IMAGE_COMMAND.format(image = shlex.quote(image))
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE
    )
    stdout_data, stderr_data = await proc.communicate()
    if proc.returncode == 0:
        return json.loads(stdout_data)
    else:
        raise TrivyError(stderr_data)
