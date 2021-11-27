from ..algos.sha256 import SHA256, pad
import json


def sha_visual(msg: bytes) -> dict:
    sha = SHA256(visual=True)
    sha.update(msg)
    padding = pad(sha._msg_len)
    return {
        'msg': msg,
        'padding': padding,
        'steps': sha.steps,
        'hash': sha.hexdigest()
    }
