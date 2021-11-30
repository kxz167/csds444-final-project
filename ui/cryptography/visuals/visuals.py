from typing import List
from ..algos.sha256 import SHA256
from ..algos.sha512 import SHA512


def sha256_visual(msg: bytes):
    sha = SHA256(visual=True)
    sha.update(msg)
    return sha.steps, sha.hexdigest()

def sha512_visual(msg: bytes):
    sha = SHA512(visual=True)
    sha.update(msg)
    return sha.steps, sha.hexdigest()