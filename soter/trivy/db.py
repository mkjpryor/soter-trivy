"""
Module containing code to update the Trivy vulnerability database.
"""

import asyncio
import json
import logging
import os
import sys
import time


# Read configuration from environment variables
#: The Trivy command to use
TRIVY_COMMAND = os.environ.get('TRIVY_COMMAND', 'trivy')
#: The database update interval in seconds (default 24 hours)
TRIVY_DB_UPDATE_INTERVAL = int(os.environ.get('TRIVY_DB_UPDATE_INTERVAL', '86400'))


logger = logging.getLogger(__name__)
logging.basicConfig(level = logging.INFO)


def run_async(func):
    """
    Decorator to make an async function synchronous by running it.
    """
    def run():
        return asyncio.run(func())
    return run


@run_async
async def exists():
    """
    Checks if the database exists.
    """
    logger.info("Checking if Trivy database exists...")
    # Instead of needing to implement logic to figure out the cache location,
    # just ask trivy what it knows using the --version flag
    # If the output has a VulnerabilityDB entry, then the db has been downloaded
    proc = await asyncio.create_subprocess_shell(
        f"{TRIVY_COMMAND} --version --format json",
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE
    )
    stdout_data, stderr_data = await proc.communicate()
    # If the process failed completely, we are done
    if proc.returncode != 0:
        logger.error('Trivy command failed: {}'.format(stderr_data.decode()))
        # Exit with the error code
        sys.exit(proc.returncode)
        return
    # If the command was successful, see if there is db info in the output
    if 'VulnerabilityDB' in json.loads(stdout_data):
        logger.info("Trivy database exists")
    else:
        logger.error("Trivy database does not exist")
        # When the database doesn't exist, make sure to exit with non-zero code
        sys.exit(1)


async def do_update():
    """
    Updates the Trivy database.
    """
    logger.info("Updating Trivy vulnerability database...")
    # Call out to the Trivy CLI to update the vulnerability database
    proc = await asyncio.create_subprocess_shell(
        f"{TRIVY_COMMAND} image --download-db-only",
        stdout = asyncio.subprocess.PIPE,
        stderr = asyncio.subprocess.PIPE
    )
    stdout_data, stderr_data = await proc.communicate()
    if proc.returncode == 0:
        logger.info('Trivy vulnerability database updated')
    else:
        logger.error('Trivy command failed: {}'.format(stderr_data.decode()))


#: Make a sync version of the database update to use as a command
update = run_async(do_update)


@run_async
async def periodic_update():
    """
    Run forever and periodically update the vulnerability database.
    """
    while True:
        await do_update()
        await asyncio.sleep(TRIVY_DB_UPDATE_INTERVAL)
