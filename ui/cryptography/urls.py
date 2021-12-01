from django.urls import path, re_path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('tools/', views.tools, name="tools"),
    path('tutorials/', views.tutorials, name="tutorials"),
    # path('file/', views.file, name="file-encode"),
    # path('text/', views.text, name="text-encode"),
    path('tutorials/file/', views.file, name="tut-file-encode"),
    path('tutorials/text/', views.text, name="tut-text-encode"),
    path('tutorials/file/result/', views.result, name="file-result"),
    path('tutorials/text/result/', views.result, name="text-result"),
    path('tools/file/', views.file, name="tool-file-encode"),
    path('tools/text/', views.text, name="tool-text-encode"),
    path('tools/file/result/', views.result, name="tool-file-result"),
    path('tools/text/result/', views.result, name="tool-text-result"),
    path('downloads/<filepath>', views.download_file, name='download_file')
    # re_path(r'.*/inc-result', views.inc_result, name="inc-result"),
    # re_path(r'.*/dec-result', views.dec_result, name="dec-result")
]