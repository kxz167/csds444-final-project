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

class ResultForm (forms.Form):
    steps = forms.JSONField()
    step_index = forms.IntegerField()
    args = forms.JSONField()



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
    if request.method == 'POST':
        form = EncryptOptionForm(request.POST, request.FILES)
        if form.is_valid():
            args = request.POST
            return render(request, 'cryptography/sha.html', {
                    'args': args, 
                    # Assuming, we are using on sha only
                    'steps': sha256_visual(bytes(args['plaintext'], 'utf-8'))
                }
            )
    else:
        enc_opt_form = EncryptOptionForm()
        text_enc_form = TextEncryptForm()
    return render(request, 'cryptography/text.html', {'encrypt_form':enc_opt_form, 'text_form':text_enc_form})

def result(request: WSGIRequest):
    if request.method == 'POST':
        form = EncryptOptionForm(request.POST, request.FILES)
        if form.is_valid():
            args = request.POST

            visual_func = {
                'sha256': sha256_visual,
                'sha512': sha512_visual
            }

            visual_temp_name = {
                'sha256': 'temp_sha256.txt',
                'sha512': 'temp_sha512.txt'
            }

            parsed_steps, output = visual_func[args['algo']](bytes(args['plaintext'], 'utf-8'))


            temp_file_name = visual_temp_name[args['algo']]
            temp_file_path = str(os.path.join(os.path.join(settings.BASE_DIR, 'temp'), temp_file_name))
            with open(temp_file_path, 'w') as temp_file:
                temp_file.write(output)

            return render(request, 'cryptography/results.html', {
                    'args': args,
                    'input': args['plaintext'],
                    'output': output,
                    'converted_file': temp_file_name,
                    'steps': parsed_steps
                }
            )
    else:
        enc_opt_form = EncryptOptionForm()
        text_enc_form = TextEncryptForm()
    return render(request, 'cryptography/text.html', {'encrypt_form':enc_opt_form, 'text_form':text_enc_form})

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

# def inc_result(request: WSGIRequest):
#     # new_index = min(len(parsed_steps-1), request.POST.step_index + 1)
#     new_index = 1
#     results = ResultForm(initial={
#                 'args': request.POST['args'],
#                 'step_index': new_index,
#                 'steps': request.POST['steps']
#             })

#     return HttpResponseRedirect(request, 'cryptography/results.html', {
#                     'resultForm': results,
#                     'args': request.POST['args'],
#                     'step_index': 0,
#                     'steps': request.POST['steps']
#                 }
#             )

# def dec_result(request: WSGIRequest):
#     new_index = max(0, request.POST.step_idx - 1)

#     return render(request, 'cryptography/results.html', {
#                     'resultForm': results,
#                     'args': args,
#                     'step_index': 0,
#                     'steps': parsed_steps
#                 }
#             )

def file(request):
    return render(request, 'cryptography/file.html', {})