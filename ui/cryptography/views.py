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
    "aes": run_the_algo,
    "rsa": rsa_visual,
    "ecies": ecies_visual,
}

ENC_ALGO = {
    "aes": aes_method,
}


# Create your views here.
def index(request):
    return render(request, 'cryptography/index.html', {})

def tools(request):
    return render(request, 'cryptography/tools.html', {})
 
def encode(request):
    return render(request, 'cryptography/encrypt.html', {'method': 'encode', 'method_display': 'Encoding'})

def decode(request):
    return render(request, 'cryptography/encrypt.html', {'method': 'decode', 'method_display': 'Decoding'})

def textEncode(request):
    return render(request, 'cryptography/encrypt.html', {'method': 'encode', 'method_display': 'Encoding'})

def textDecode(request):
    return render(request, 'cryptography/encrypt.html', {'method': 'decode', 'method_display': 'Decoding'})

def enc_result(request: WSGIRequest):
    print("Begin computing results")
    args = request.POST
    files = request.FILES
    
    print(args)
    print(files)

    algorithm = args['algo']
    method = args['method'] #whether we are encoding or decoding
    method_display = args['method_display'] #Displayable encryption type: Encoding or Decoding.
    key_is_file = 'key_is_file' in args
    input_is_file = 'input_is_file' in args

    # Write the key file (BYTES): Can change to toher formats
    with open('uploads/enc_key_file', 'wb+') as destination: #Modify wb
        if(key_is_file):
            for chunk in files['key_file'].chunks():
                destination.write(chunk)
        else:
            if args['keytext'].isnumeric():
                # Note: 196-bits is AES max -> 24 bytes key
                destination.write(int(args['keytext']).to_bytes(24, 'big'))
            else: 
                destination.write(args['keytext'].encode('utf-8')) #Remove encode

    # Write the plain file (BYTES): Can change to toher formats
    with open('uploads/enc_plain_file', 'wb+') as destination: #Modify wb
        if(input_is_file):
            for chunk in files['plain_file'].chunks():
                destination.write(chunk)
        else:
            destination.write(args['plaintext'].encode('utf-8')) #Remove encode
    
    results = ENC_ALGO[algorithm]('uploads/enc_plain_file', 'uploads/enc_key_file', method) # In file paths ONLY

    #If necessary, can read the results files or hoever results are returned

    return render(request, 'cryptography/encrypt-results.html', {
            'algorithm': algorithm,
            'method': method,
            'method_display': method_display,
            'results': results
        }
    )

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
        results, parsed_steps = ALGO[algorithm](input_text, False, showstep)
    else:
        # This is a file
        # Upload the file to 'uploads/plain_file'
        with open('uploads/plain_file', 'wb+') as destination:
            for chunk in files['plain_file'].chunks():
                destination.write(chunk)
        
        results, parsed_steps = ALGO[algorithm]('uploads/plain_file', True, showstep) # Must load algorithms

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
    name = os.path.basename(filepath)
    path = open(filepath, 'rb')
    # Set the mime type
    mime_type, _ = mimetypes.guess_type(filepath)
    # Set the return value of the HttpResponse
    response = HttpResponse(path, content_type=mime_type)
    # Set the HTTP header for sending to browser
    response['Content-Disposition'] = f"attachment; filename={name}"
    # Return the response value
    return response