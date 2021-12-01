from typing import List
import os

from ..algos.drivers import *
from ..algos.sha256 import SHA256
from ..algos.sha512 import SHA512
from ..algos.ECIES.ecies import *
from django.conf import settings


def sha256_visual(msg: str, is_file=False, showstep=False):
    sha = SHA256(visual=showstep)
    bytes_msg = None
    if not is_file:
        bytes_msg = bytes(msg, 'utf-8')
        sha.update(bytes_msg)
    else:
        with open(msg, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                sha.update(chunk)

    temp_file_name = 'encoded'
    temp_file_path = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), temp_file_name))
    with open(temp_file_path, 'w') as temp_file:
        temp_file.write(sha.hexdigest())

    return {'string_text': sha.hexdigest(), 'file': {'Hash File': temp_file_path}}, sha.steps

def sha512_visual(msg: str, is_file=False, showstep=False):
    sha = SHA512(visual=showstep)
    bytes_msg = None
    if not is_file:
        bytes_msg = bytes(msg, 'utf-8')
        sha.update(bytes_msg)
    else:
        with open(msg, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                sha.update(chunk)

    temp_file_name = 'encoded'
    temp_file_path = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), temp_file_name))
    with open(temp_file_path, 'w') as temp_file:
        temp_file.write(sha.hexdigest())
    return {'string_text': sha.hexdigest(), 'file': {'Hash File': temp_file_path}}, sha.steps

def ecies_visual(msg: str, is_file: bool=False, showstep: bool=False):
    return to_string(ecies(msg, is_filepath=is_file))

def aes_method(msg_path, key_path, method):
    if method == 'decode':
        return aes_dec(msg_path, key_path)
    elif method == 'encode':
        return aes_enc(msg_path, key_path)
    else:
        return {'string_text': "what??, how did you get here????"}

def aes_enc(msg_path: str, key_path: str):
    key = int.from_bytes(open(key_path, 'rb').read(), 'big')
    encoded = aes_encrypt(msg_path, key, is_file=True)
    decoded = aes_decrypt(encoded, key, is_file=True)

    res, _ = sha256_visual(msg_path, is_file=True)
    sha256_orig = res["string_text"]
    res, _ = sha256_visual(decoded, is_file=True)
    sha256_decoded = res["string_text"]


    return {
        'string_text': f"Key is : {key}<br>" +
                        f"SHA256 of the original: {sha256_orig}<br>" +
                        f"SHA256 of the decoded file with the same key: {sha256_decoded}<br>",
        'file': {
            "Decoded": str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), 'aes_decoded')),
            "Encoded": str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), 'aes_encoded'))
        }
    }

def aes_dec(msg_path: str, key_path: str):
    key = int.from_bytes(open(key_path, 'rb').read(), 'big')
    decoded = aes_decrypt(msg_path, key, is_file=True)
    res, _ = sha256_visual(decoded, is_file=True)
    sha256_decoded = res["string_text"]


    return {
        'string_text': f"Key is : {key}<br>" +
                        f"SHA256 of the decoded file with key above: {sha256_decoded}<br>",
        'file': {
            "Decoded": str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), 'aes_decoded')),
        }
    }