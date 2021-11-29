from django.shortcuts import render
from django.http import HttpResponse
from django.core.handlers.wsgi import WSGIRequest

from django.template import loader

from django.shortcuts import render
from django import forms

from django.conf import settings

import os
import mimetypes

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

class UploadFileForm (forms.Form):
    title = forms.CharField(max_length = 50)
    file = forms.FileField()

class EncryptForm (forms.Form):
    title = forms.CharField(max_length = 50)
    algo = forms.MultipleChoiceField(choices = ENCRYPTION_TYPES)
    method = forms.MultipleChoiceField(choices = INPUT_TYPES)
    file = forms.FileField()

class EncryptOptionForm (forms.Form):
    show_step = forms.BooleanField()
    show_step_description = forms.BooleanField()
    pause_on_step = forms.BooleanField()

class TextEncryptForm (forms.Form):
    body = forms.CharField(widget=forms.Textarea, label="body",required=True)

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
    if request.method == 'POST':
        form = EncryptForm(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_file(request.FILES['file'])
            return HttpResponseRedirect('/success/url/')
    else:
        form = EncryptForm()
    return render(request, 'cryptography/index.html', {'form': form})

# From django
def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_file(request.FILES['file'])
            return HttpResponseRedirect('/success/url/')
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})

def text(request: WSGIRequest):
    if request.method == 'POST':
        form = EncryptOptionForm(request.POST, request.FILES)
        if form.is_valid():
            args = request.POST
            steps = sha_visual(bytes(args['plaintext'], 'utf-8'))
            temp_file_name = 'temp_sha.txt'
            temp_file_path = str(os.path.join(settings.BASE_DIR, f'temp/{temp_file_name}'))
            with open(temp_file_path, 'w') as temp_file:
                temp_file.write(steps['hash'])
            return render(request, 'cryptography/sha_bs5.html', {
                    'args': args, 
                    # Assuming, we are using on sha only
                    'steps': steps,
                    'converted_file': temp_file_name
                }
            )
    else:
        enc_opt_form = EncryptOptionForm()
        text_enc_form = TextEncryptForm()
    return render(request, 'cryptography/text.html', {'encrypt_form':enc_opt_form, 'text_form':text_enc_form})

def file(request):
    return render(request, 'cryptography/file.html', {})

def download_file(request, filename):
    filepath = str(os.path.join(settings.BASE_DIR, f'temp/{filename}'))
    path = open(filepath, 'r')
    # Set the mime type
    mime_type, _ = mimetypes.guess_type(filepath)
    # Set the return value of the HttpResponse
    response = HttpResponse(path, content_type=mime_type)
    # Set the HTTP header for sending to browser
    response['Content-Disposition'] = f"attachment; filename={filename}"
    # Return the response value
    return response

