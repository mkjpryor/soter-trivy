"""
Module providing the ASGI app for soter-trivy.
"""

import asyncio
import json
import itertools
import logging
import os
import re
import shlex

from quart import Quart

from jsonrpc.model import JsonRpcException

from jsonrpc.server import Dispatcher
from jsonrpc.server.adapter.quart import websocket_blueprint

from ..scanner.models import ScannerStatus, Image, Severity, PackageType, ImageVulnerability


# The preferred reference sources, in order of preference
PREFERRED_REFERENCES = [
    'cve.mitre.org',
    'redhat.com',
    'debian.org',
    'gentoo.org',
    'opensuse.org',
    'suse.com',
    'python.org',
    'oracle.com',
]


# Super-simple regex to extract a URL
URL_REGEX = re.compile(r'(https?://\S+)')


# Configuration options
#: The Trivy command to use
TRIVY_COMMAND = os.environ.get('TRIVY_COMMAND', 'trivy')
#: The number of concurrent scans to allow per worker
TRIVY_CONCURRENT_SCANS = int(os.environ.get('TRIVY_CONCURRENT_SCANS', '1'))


class TrivyError(JsonRpcException):
    """
    Raised when there is an error calling out to the Trivy CLI.
    """
    message = "Trivy error"
    code = 100


# Build the Quart app
app = Quart(__name__)
# Register the JSON-RPC blueprint
dispatcher = Dispatcher()
app.register_blueprint(websocket_blueprint(dispatcher), url_prefix = '/')


logger = logging.getLogger(__name__)


@dispatcher.register
async def status():
    """
    Return status information for the scanner.
    """
    # Call out to the Trivy CLI to get version information
    proc = await asyncio.create_subprocess_shell(
        f"{TRIVY_COMMAND} --version --format json",
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE
    )
    stdout_data, stderr_data = await proc.communicate()
    if proc.returncode == 0:
        version_info = json.loads(stdout_data)
        version = version_info['Version']
        available = True
        message = 'available'
        properties = {
            f"vulnerabilitydb/{key.lower()}": str(value)
            for key, value in version_info.get('VulnerabilityDB', {}).items()
        }
    else:
        logger.error('Trivy command failed: {}'.format(stderr_data.decode()))
        version = 'unknown'
        available = False
        message = 'could not detect status'
        properties = None
    return ScannerStatus(
        kind = 'Trivy',
        vendor = 'Aqua Security',
        version = version,
        available = available,
        message = message,
        properties = properties
    )


def select_reference(references):
    """
    Extracts the preferred URL from the references for a vulnerability.
    """
    # Some Trivy references aren't just URLs, but do have URLs embedded in them
    # So extract the urls from the references
    reference_urls = list(itertools.chain.from_iterable(
        URL_REGEX.findall(reference)
        for reference in references
    ))
    # Return one of the preferred URLs if possible
    for pref in PREFERRED_REFERENCES:
        try:
            return next(url for url in reference_urls if pref in url)
        except StopIteration:
            pass
    # By default, return the first url
    return next(iter(reference_urls), None)


@app.before_serving
async def create_semaphore():
    """
    Create a semaphore that we will use to limit concurrency of scanning
    """
    app.scan_semaphore = asyncio.Semaphore(TRIVY_CONCURRENT_SCANS)


@dispatcher.register
async def scan_image(image):
    """
    Scans the given image and returns vulnerability information.
    """
    # Parse the image using the model
    image = Image.parse_obj(image)
    async with app.scan_semaphore:
        # Call out to Trivy to scan the image
        # Make sure we don't update the vulnerability database
        # In order to avoid hitting Trivy's rate limiting, we fetch the database
        # periodically using a separate process
        proc = await asyncio.create_subprocess_shell(
            "{} --quiet image --skip-update --format json {}".format(
                TRIVY_COMMAND,
                shlex.quote(image.full_digest)
            ),
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE
        )
        stdout_data, stderr_data = await proc.communicate()
    if proc.returncode != 0:
        raise TrivyError(stderr_data)
    result = json.loads(stdout_data)
    if result:
        return [
            ImageVulnerability(
                title = vuln['VulnerabilityID'],
                severity = Severity[vuln['Severity'].upper()],
                info_url = select_reference(vuln.get('References') or []),
                package_name = vuln['PkgName'],
                package_version = vuln['InstalledVersion'],
                package_type = PackageType.OS,
                package_location = None,
                fix_version = vuln.get('FixedVersion')
            )
            for vuln in (result[0]['Vulnerabilities'] or [])
        ]
    else:
        return []
