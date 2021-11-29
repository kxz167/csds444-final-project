from ..algos.sha256 import SHA256, pad
import json
from bitstring import BitArray


def sha_visual(msg: bytes) -> dict:
    sha = SHA256(visual=True)
    sha.update(msg)
    padding = pad(sha._msg_len)
    return {
        'msg': msg.decode('utf-8', errors='ignore'),
        'padding': BitArray(bytes=padding).bin,
        'steps': sha.steps,
        'hash': sha.hexdigest()
    }
