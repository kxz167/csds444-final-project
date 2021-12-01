from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.core.handlers.wsgi import WSGIRequest

from django.template import loader

from django.shortcuts import render
from django import forms

from .visuals.visuals import *
import os
import mimetypes
from django.conf import settings

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

ALGO = {
    "sha256": sha256_visual,
    "sha512": sha512_visual,
    # "aes": ,
    # "rsa": ,
    "ecies": ecies_visual,
}


# Create your views here.
def index(request):
    return render(request, 'cryptography/index.html', {})

def tools(request):
    return render(request, 'cryptography/tools.html', {})

def tutorials(request):
    return render(request, 'cryptography/tutorials.html', {})

def text(request: WSGIRequest):
    return render(request, 'cryptography/text.html', {})

def file(request):
    # enc_opt_form = EncryptOptionForm()
    return render(request, 'cryptography/file.html', {})

def result(request: WSGIRequest):
    print("Begin computing results")
    args = request.POST
    files = request.FILES

    algorithm = args['algo']
    showstep = 'show_step' in args and args['show_step'] == 'on'

    input_type = args['formType']
    if(input_type == "text"):
        input_text = args['plaintext']
        results, parsed_steps = ALGO[algorithm](input_text, is_file=False, showstep=showstep)
        print(results)
    else:
        # This is a file
        # Upload the file to 'uploads/plain_file'
        with open('uploads/plain_file', 'wb+') as destination:
            for chunk in files['plain_file'].chunks():
                destination.write(chunk)
        
        results, parsed_steps = ALGO[algorithm]('uploads/plain_file', is_file=True, showstep=showstep) # Must load algorithms

    # print(algorithm)
    # print(showstep)
    # print(type(showstep))

    # print(args)
    # print(files)

    return render(request, 'cryptography/results.html', {
            # 'resultForm': results,
            # 'args': args,
            'steps': parsed_steps,
            'algorithm': algorithm,
            'showstep': showstep,
            'input_type': input_type,
            'results': results
        }
    )

def download_file(request, filepath):
    path = open(filepath, 'r')
    # Set the mime type
    mime_type, _ = mimetypes.guess_type(filepath)
    # Set the return value of the HttpResponse
    response = HttpResponse(path, content_type=mime_type)
    # Set the HTTP header for sending to browser
    response['Content-Disposition'] = f"attachment; filename=encoded"
    # Return the response value
    return response