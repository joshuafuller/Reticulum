#!/usr/bin/env python3

# Reticulum License
#
# Copyright (c) 2016-2026 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
import RNS
import struct
import base64
import argparse

from RNS.Utilities.rnid import validate_rsg, create_rsg, extract_signed_rsg_data

SSHSIG_MAGIC = b"SSHSIG"
SSHSIG_VERSION = 1
NAMESPACE_GIT = b"git"
RESERVED_EMPTY = b""
HASH_ALGORITHM = b"sha256"

def ssh_string(data): return struct.pack(">I", len(data)) + data

def read_ssh_string(data, offset):
    if offset + 4 > len(data): raise ValueError("Not enough data for string length")
    length = struct.unpack(">I", data[offset:offset+4])[0]
    if offset + 4 + length > len(data): raise ValueError("Not enough data for string content")
    return data[offset+4:offset+4+length], offset + 4 + length

def create_ssh_signature(public_key_wire, namespace, reserved, hash_algorithm, signature_data):
    # SSHSIG (6 bytes) || version (uint32) || pubkey (ssh-string) || namespace (ssh-string) ||
    # reserved (ssh-string) || hash_algorithm (ssh-string) || signature (ssh-string)
    sig_blob = SSHSIG_MAGIC
    sig_blob += struct.pack(">I", SSHSIG_VERSION)
    sig_blob += ssh_string(public_key_wire)
    sig_blob += ssh_string(namespace)
    sig_blob += ssh_string(reserved)
    sig_blob += ssh_string(hash_algorithm)
    sig_blob += ssh_string(signature_data)
    return sig_blob

def parse_ssh_signature(sig_data):
    offset = 0

    if not sig_data.startswith(SSHSIG_MAGIC): raise ValueError("Invalid SSH signature: missing SSHSIG magic")
    offset += len(SSHSIG_MAGIC)

    if offset + 4 > len(sig_data): raise ValueError("Invalid SSH signature: truncated")
    version = struct.unpack(">I", sig_data[offset:offset+4])[0]
    if version != SSHSIG_VERSION: raise ValueError(f"Unsupported SSH signature version: {version}")
    offset += 4

    public_key, offset     = read_ssh_string(sig_data, offset)
    namespace, offset      = read_ssh_string(sig_data, offset)
    reserved, offset       = read_ssh_string(sig_data, offset)
    hash_algorithm, offset = read_ssh_string(sig_data, offset)
    signature_data, offset = read_ssh_string(sig_data, offset)

    return { "version": version,
             "public_key": public_key,
             "namespace": namespace,
             "reserved": reserved,
             "hash_algorithm": hash_algorithm,
             "signature_data": signature_data }

def armor_ssh_signature(sig_blob):
    b64_data = base64.b64encode(sig_blob).decode('ascii')
    lines = [b64_data[i:i+70] for i in range(0, len(b64_data), 70)]

    result = "-----BEGIN SSH SIGNATURE-----\n"
    result += "\n".join(lines) + "\n"
    result += "-----END SSH SIGNATURE-----\n"
    return result

def unarmor_ssh_signature(armored_data):
    lines = armored_data.strip().split('\n')
    b64_data = ""
    in_sig = False

    for line in lines:
        if 'BEGIN SSH SIGNATURE' in line: in_sig = True; continue
        if 'END SSH SIGNATURE' in line: break
        if in_sig: b64_data += line.strip()

    if not b64_data: raise ValueError("No signature data found in armored input")

    return base64.b64decode(b64_data)

def get_pubkey_wire_format(identity):
    return ssh_string(b"ssh-ed25519")+ssh_string(identity.sig_pub_bytes)

def sign(args):
    keyfile = args.keyfile
    if not keyfile or not os.path.isfile(keyfile):
        print(f"Identity file not found: {keyfile}", file=sys.stderr)
        return 1

    try:
        identity = RNS.Identity.from_file(keyfile)
        if not identity or not identity.get_private_key():
            print("Error: Could not load identity or identity has no private key", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"Error loading identity: {e}", file=sys.stderr)
        return 1

    if args.file and os.path.isfile(args.file):
        with open(args.file, 'rb') as f: message = f.read()
        sig_file = args.file + ".sig"
    else:
        message = sys.stdin.buffer.read()
        sig_file = None

    try: rsg = create_rsg(identity, message)
    except Exception as e:
        print(f"Error creating signature: {e}", file=sys.stderr)
        return 1

    try: ssh_pubkey = get_pubkey_wire_format(identity)
    except Exception as e:
        print(f"Error converting public key: {e}", file=sys.stderr)
        return 1

    try:
        ssh_sig = create_ssh_signature(public_key_wire=ssh_pubkey, namespace=NAMESPACE_GIT, reserved=RESERVED_EMPTY,
                                       hash_algorithm=HASH_ALGORITHM, signature_data=rsg)
    except Exception as e:
        print(f"Error creating SSH signature: {e}", file=sys.stderr)
        return 1

    try: armored = armor_ssh_signature(ssh_sig)
    except Exception as e:
        print(f"Error armoring signature: {e}", file=sys.stderr)
        return 1

    if sig_file:
        try:
            with open(sig_file, 'w') as f: f.write(armored)
        except Exception as e:
            print(f"Error writing signature file: {e}", file=sys.stderr)
            return 1

    else: print(armored, end="")
    
    return 0

def find_principals(args):
    sigfile = args.sigfile
    if not sigfile or not os.path.isfile(sigfile): print("Error: Signature file not found", file=sys.stderr); return 1

    try:
        with open(sigfile, 'r') as f: armored_sig = f.read()
    except Exception as e: print(f"Error reading signature file: {e}", file=sys.stderr); return 1

    try: ssh_sig = parse_ssh_signature(unarmor_ssh_signature(armored_sig))
    except Exception as e: print(f"Error parsing SSH signature: {e}", file=sys.stderr); return 1

    if ssh_sig["namespace"] != NAMESPACE_GIT:
        print(f"Error: Namespace mismatch: {ssh_sig['namespace']}", file=sys.stderr)
        return 1

    rsg = ssh_sig["signature_data"]
    try: identity_hash = extract_signed_rsg_data(rsg)["meta"]["signer"]
    except Exception as e: print(f"Could not determine signer identity: {e}", file=sys.stderr); return 1

    print(RNS.hexrep(identity_hash, delimit=False))
    return 0

def check_novalidate(args):
    sigfile = args.sigfile
    if not sigfile or not os.path.isfile(sigfile): return 1

    try:
        with open(sigfile, 'r') as f: armored_sig = f.read()
        ssh_sig = parse_ssh_signature(unarmor_ssh_signature(armored_sig))

        if ssh_sig["namespace"] != NAMESPACE_GIT: return 1

        rsg = ssh_sig["signature_data"]
        signed_data = extract_signed_rsg_data(rsg)
        if not signed_data: return 1
        else:               return 0

    except Exception: return 1

def extract_commit_author(message):
    message_lines = message.splitlines()
    author = ""
    AUTHOR_TARGET = b"author "
    for line in message_lines:
        if not line.strip(b""): break
        elif line.startswith(AUTHOR_TARGET):
            try:
                spos = line.find(b"<"); epos = line.find(b">")
                if spos > len(AUTHOR_TARGET) and epos > spos and epos < len(line)-1:
                    author = line[spos+1:epos].decode("utf-8")
                    break
            except Exception as e: print(f"Error while determining author from signed commit"); return 1

    return author

def extract_commit_committer(message):
    message_lines = message.splitlines()
    committer = ""
    COMMITTER_TARGET = b"committer "
    for line in message_lines:
        if not line.strip(b""): break
        elif line.startswith(COMMITTER_TARGET):
            try:
                spos = line.find(b"<"); epos = line.find(b">")
                if spos > len(COMMITTER_TARGET) and epos > spos and epos < len(line)-1:
                    committer = line[spos+1:epos].decode("utf-8")
                    break
            except Exception as e: print(f"Error while determining committer from signed commit"); return 1

    return committer

def extract_commit_tagger(message):
    message_lines = message.splitlines()
    tagger = ""
    is_tag = False
    for line in message_lines:
        TAG_TARGET = b"tag "
        TAGGER_TARGET = b"tagger "
        if not line.strip(b""): break
        elif line.startswith(TAG_TARGET): is_tag = True
        elif line.startswith(TAGGER_TARGET) and is_tag:
            try:
                spos = line.find(b"<"); epos = line.find(b">")
                if spos > len(TAGGER_TARGET) and epos > spos and epos < len(line)-1:
                    tagger = line[spos+1:epos].decode("utf-8")
                    break
            except Exception as e: print(f"Error while determining tagger from signed commit"); return 1

    return tagger, is_tag

def verify(args):
    sigfile = args.sigfile
    principal = args.principal
    if not sigfile or not os.path.isfile(sigfile): print("Error: Signature file not found", file=sys.stderr); return 1

    message = sys.stdin.buffer.read()

    try:
        with open(sigfile, 'r') as f: armored_sig = f.read()
        raw_sig = unarmor_ssh_signature(armored_sig)
        ssh_sig = parse_ssh_signature(raw_sig)

    except Exception as e: print(f"Error parsing signature: {e}", file=sys.stderr); return 1

    author         = extract_commit_author(message)
    committer      = extract_commit_committer(message)
    tagger, is_tag = extract_commit_tagger(message)

    if ssh_sig["namespace"] != NAMESPACE_GIT: print(f"Invalid commit signature namespace", file=sys.stderr); return 1

    rsg = ssh_sig["signature_data"]
    valid, signed_data, signing_identity = validate_rsg(rsg, message)
    
    if not valid: print(f"Invalid signature", file=sys.stderr); return 1

    if is_tag: author = tagger

    signer_hash = RNS.hexrep(signing_identity.hash, delimit=False)
    if not author == signer_hash: print(f"Commit not signed by author <{author}>"); return 1
    
    if principal:
        if principal != signer_hash: print(f"Principal mismatch", file=sys.stderr); return 1

    print(f"Good \"git\" signature for commit, signed with Reticulum Identity key <{signer_hash}>")
    return 0

def main():
    parser = argparse.ArgumentParser(description="Git commit signer and validator")
    parser.add_argument("-Y", dest="op", required=True, choices=["sign", "find-principals", "check-novalidate", "verify"], help="Operation to perform")
    parser.add_argument("-n", dest="namespace", default="git", help="Namespace")
    parser.add_argument("-f", dest="keyfile", help="Key file (for signing) or allowed signers file (for verification)")
    parser.add_argument("-I", dest="principal", help="Principal identity (for verification)")
    parser.add_argument("-s", dest="sigfile", help="Signature file")
    parser.add_argument("file", nargs="?", help="File to sign (for signing)")
    parser.add_argument("-O", dest="ssh_options", action="append", default=[], help="SSH options (for git compatibility, ignored)")
    
    args, unknown = parser.parse_known_args()
    for arg in unknown:
        if arg.startswith('-O'): continue # TODO: Add options for time validation
        else:
            print(f"Error: Unknown argument: {arg}", file=sys.stderr)
            sys.exit(1)

    if   args.op == "sign":             return sign(args)
    elif args.op == "find-principals":  return find_principals(args)
    elif args.op == "check-novalidate": return check_novalidate(args)
    elif args.op == "verify":           return verify(args)
    else:
        print(f"Error: Unknown operation: {args.op}", file=sys.stderr)
        return 1

if __name__ == "__main__": sys.exit(main())