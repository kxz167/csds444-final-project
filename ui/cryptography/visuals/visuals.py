from typing import List
import os
from ..algos.sha256 import SHA256
from ..algos.sha512 import SHA512
from ..algos.ECIES.ecies import *
from django.conf import settings


def sha256_visual(msg: str, is_file=False, showstep=False):
    bytes_msg = None
    if not is_file:
        bytes_msg = bytes(msg, 'utf-8')
    else:
        bytes_msg = open(msg, 'rb').read(-1)
        
    sha = SHA256(visual=showstep)
    sha.update(bytes_msg)

    temp_file_name = 'encoded'
    temp_file_path = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), temp_file_name))
    with open(temp_file_path, 'w') as temp_file:
        temp_file.write(sha.hexdigest())

    return {'string_text': sha.hexdigest(), 'files': {'Hash File': temp_file_path}}, sha.steps

def sha512_visual(msg: str, is_file=False, showstep=False):
    bytes_msg = None
    if not is_file:
        bytes_msg = bytes(msg, 'utf-8')
    else:
        bytes_msg = open(msg, 'rb').read(-1)
    sha = SHA512(visual=showstep)
    sha.update(bytes_msg)

    temp_file_name = 'encoded'
    temp_file_path = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), temp_file_name))
    with open(temp_file_path, 'w') as temp_file:
        temp_file.write(sha.hexdigest())
    return {'string_text': sha.hexdigest(), 'files': {'Hash File': temp_file_path}}, sha.steps

def ecies_visual(msg: str, is_file: bool=False, showstep: bool=False):
    return to_string(ecies(msg, is_filepath=is_file))
