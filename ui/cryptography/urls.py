from django.urls import path, re_path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('tutorials/', views.tutorials, name="tutorials"),
    path('tutorials/file/', views.file, name="tut-file-encode"),
    path('tutorials/text/', views.text, name="tut-text-encode"),
    path('tutorials/file/result/', views.result, name="file-result"),
    path('tutorials/text/result/', views.result, name="text-result"),
    path('tools/', views.tools, name="tools"),
    path('tools/encode/', views.encode, name="tools-encode"),
    path('tools/decode/', views.decode, name="tools-decode"),
    path('tools/encode/result/', views.enc_result, name="tools-encode-result"),
    path('tools/decode/result/', views.enc_result, name="tools-decode-result"),
    path('downloads/<filepath>', views.download_file, name='download_file')
    # re_path(r'.*/inc-result', views.inc_result, name="inc-result"),
    # re_path(r'.*/dec-result', views.dec_result, name="dec-result")
]