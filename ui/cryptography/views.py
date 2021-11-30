from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.core.handlers.wsgi import WSGIRequest

from django.template import loader

from django.shortcuts import render
from django import forms

from .visuals.sha256_visuals import sha_visual

ENCRYPTION_TYPES = (
    ("1", "SHA256"),
    ("2", "SHA512"),
    ("3", "AES"),
    ("4", "ERC"),
)

INPUT_TYPES = (
    ("1", "Text"),
    ("2", "File")
)

FILE_ALGO = {
    # "sha256": ,
    # "sha512": ,
    # "aes": ,
    # "rsa": ,
    # "ecies": ,
}

TEXT_ALGO = {
    # "sha256": ,
    # "sha512": ,
    # "aes": ,
    # "rsa": ,
    # "ecies": ,
}


# Create your views here.
def index(request):
    return render(request, 'cryptography/index.html', {})


def text(request: WSGIRequest):
    return render(request, 'cryptography/text.html', {})

def file(request):
    # enc_opt_form = EncryptOptionForm()
    return render(request, 'cryptography/file.html', {})

def result(request: WSGIRequest):
    args = request.POST
    files = request.FILES

    algorithm = args['algo']
    showstep = 'show_step' in args and args['show_step'] == 'on'

    input_type = args['formType']
    if(input_type == "text"):
        # This is a text
        input_text = args['plaintext']
        # parsed_steps = TEXT_ALGO[algorithm](input_text)
        parsed_steps = sha_visual(bytes(input_text, 'utf-8')) # Test, use line above when loaded
    else:
        # This is a file
        # Upload the file to 'uploads/plain_file'
        with open('uploads/plain_file', 'wb+') as destination:
            for chunk in files['plain_file'].chunks():
                destination.write(chunk)
        
        parsed_steps = FILE_ALGO[algorithm]('uploads/plain_file') # Must load algorithms

    return render(request, 'cryptography/results.html', {
            # 'resultForm': results,
            # 'args': args,
            'steps': parsed_steps,
            'algorithm': algorithm,
            'showstep': showstep,
            'input_type': input_type,
        }
    )