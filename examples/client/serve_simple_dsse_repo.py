"""Serve simple DSSE repo (demo).

Serves ad-hoc generated top-level metadata and single target file from
localhost to be used with example client with the ``--use-dsse`` flag.

"""

import os
import socketserver
import sys
import tempfile
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler
from pathlib import Path

from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibKey, SSlibSigner

from tuf.api.dsse import (
    TOP_LEVEL_ROLE_NAMES,
    Envelope,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

# Define metadata expiration date as 7 days from now
expiry = datetime.utcnow().replace(microsecond=0) + timedelta(days=7)

# Create top-level roles
roles = {}
roles["root"] = Root()
roles["timestamp"] = Timestamp()
roles["snapshot"] = Snapshot()
roles["targets"] = Targets()

# Create single key pair for all roles
key = generate_ed25519_key()
public_key = SSlibKey.from_securesystemslib_key(key)
signer = SSlibSigner(key)

# Perform top-level delegation, i.e. authorize signing keys for top-level roles in root
for role_name in TOP_LEVEL_ROLE_NAMES:
    roles["root"].add_key(public_key, role_name)

# Serve metadata and target file from temporary directory.
with tempfile.TemporaryDirectory() as tmp_dir:
    repo_dir = Path(tmp_dir)
    metadata_dir = repo_dir / "metadata"
    target_dir = repo_dir / "targets"
    target_name = "file1.txt"
    target_path = target_dir / target_name

    # Create metadata and targets dirs, and target file
    os.mkdir(metadata_dir)
    os.mkdir(target_dir)
    with open(target_path, "wt") as target_file:
        target_file.write("hello dsse!")

    # Add info about target file to targets role, and create hash prefixed
    # symlinks to the target file in the repository, which is required by the client for
    # target file path resolution.
    target_file_info = TargetFile.from_file(target_name, target_path)
    for digest in target_file_info.hashes.values():
        TARGET_ALIAS = target_dir / f"{digest}.{target_name}"
        os.symlink(target_name, TARGET_ALIAS)

    roles["targets"].targets = {target_name: target_file_info}

    # Set expiration, and sign and persist all metadata. All metadata filenames are prefixed
    # with their version number except timestamp.
    for role_name, role in roles.items():
        role.expires = expiry
        envelope = Envelope.from_signed(role)
        envelope.sign(signer)
        if role_name == "timestamp":
            filename = "timestamp.json"
        else:
            filename = f"{role.version}.{role_name}.json"
        path = metadata_dir / filename

        with open(path, "wb") as f:
            f.write(envelope.to_bytes())

    # Serve HTTP
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=repo_dir, **kwargs)

    port = 8001
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(
            f"Serving TUF repo on http://127.0.0.1:{port}/\n\n"
            "Example client usage:\n"
            " \t./client tofu\n"
            " \t./client download --use-dsse file1.txt\n"
        )
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(
                "\nKeyboard interrupt ... stopping server ... removing repo ..."
            )
            sys.exit(0)
