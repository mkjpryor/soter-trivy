"""
Module providing the ASGI app for soter-trivy.
"""

import asyncio
import json
import itertools
import os
import re
import shlex

from quart import Quart

from jsonrpc.model import JsonRpcException

from jsonrpc.server import Dispatcher
from jsonrpc.server.adapter.quart import websocket_blueprint

from .scanner.models import ScannerStatus, Image, Severity, PackageType, ImageVulnerability


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


# Trivy command to use
TRIVY_COMMAND = os.environ.get('TRIVY_COMMAND', 'trivy')


class TrivyError(JsonRpcException):
    """
    Raised when there is an error calling out to the Trivy CLI.
    """
    message = "Trivy error"
    code = 100


dispatcher = Dispatcher()


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
    if proc.returncode != 0:
        raise TrivyError(stderr_data)
    version_info = json.loads(stdout_data)
    return ScannerStatus(
        kind = 'Trivy',
        vendor = 'Aqua Security',
        version = version_info['Version'],
        available = True,
        message = 'available',
        properties = {
            f"vulnerabilitydb/{key.lower()}": str(value)
            for key, value in version_info['VulnerabilityDB'].items()
        }
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


@dispatcher.register
async def scan_image(image):
    """
    Scans the given image and returns vulnerability information.
    """
    # Parse the image using the model
    image = Image.parse_obj(image)
    # Call out to Trivy to scan the image
    proc = await asyncio.create_subprocess_shell(
        "{} --quiet image --format json {}".format(
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
            for vuln in result[0]['Vulnerabilities']
        ]
    else:
        return []


# Build the Quart app
app = Quart(__name__)
# Register the JSON-RPC blueprint
app.register_blueprint(websocket_blueprint(dispatcher), url_prefix = '/')
