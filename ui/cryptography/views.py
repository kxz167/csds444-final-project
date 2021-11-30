from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.core.handlers.wsgi import WSGIRequest

from django.template import loader

from django.shortcuts import render
from django import forms

from .visuals.visuals import sha256_visual, sha512_visual
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
    # "ecies": ,
}


# class EncryptForm (forms.Form):
#     title = forms.CharField(max_length = 50)
#     algo = forms.MultipleChoiceField(choices = ENCRYPTION_TYPES)
#     method = forms.MultipleChoiceField(choices = INPUT_TYPES)
#     file = forms.FileField()

# class EncryptOptionForm (forms.Form):
#     show_step = forms.BooleanField()
#     show_step_description = forms.BooleanField()
#     pause_on_step = forms.BooleanField()

# class TextEncryptForm (forms.Form):
#     body = forms.CharField(widget=forms.Textarea, label="body",required=True)

# class ResultForm (forms.Form):
#     steps = forms.JSONField()
#     step_index = forms.IntegerField()
#     args = forms.JSONField()



# Create your views here.
def index(request):
    # template = loader.get_template("cryptography/index.html")
    # context = {
    #     "my_value": 1
    # }
    # return HttpResponse(template.render(context, request))

    # Alternatively:
    # context = {
    #     "my_value": 1
    # }
    # return render(request, 'cryptography/index.html', context)

    # Forms:
    # if request.method == 'POST':
    #     form = EncryptForm(request.POST, request.FILES)
    #     if form.is_valid():
    #         handle_uploaded_file(request.FILES['file'])
    #         return HttpResponseRedirect('/success/url/')
    # else:
    #     form = EncryptForm()
    return render(request, 'cryptography/index.html', {})

# From django
# def upload_file(request):
#     if request.method == 'POST':
#         form = UploadFileForm(request.POST, request.FILES)
#         if form.is_valid():
#             handle_uploaded_file(request.FILES['file'])
#             return HttpResponseRedirect('/success/url/')
#     else:
#         form = UploadFileForm()
#     return render(request, 'upload.html', {'form': form})

def text(request: WSGIRequest):
    # if request.method == 'POST':
    #     form = EncryptOptionForm(request.POST, request.FILES)
    #     if form.is_valid():
    #         args = request.POST
    #         return render(request, 'cryptography/sha.html', {
    #                 'args': args, 
    #                 # Assuming, we are using on sha only
    #                 'steps': sha_visual(bytes(args['plaintext'], 'utf-8'))
    #             }
    #         )
    # else:
    # enc_opt_form = EncryptOptionForm()
    # text_enc_form = TextEncryptForm()
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
        input_text = args['plaintext']
        results, parsed_steps = ALGO[algorithm](input_text, is_file=False, showstep=showstep)
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