from django.urls import path, re_path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('tools/', views.tools, name="tools"),
    path('tutorials/', views.tutorials, name="tutorials"),
    path('file/', views.file, name="file-encode"),
    path('text/', views.text, name="text-encode"),
    path('file/result/', views.result, name="file-result"),
    path('text/result/', views.result, name="text-result"),
    path('downloads/<filepath>', views.download_file, name='download_file')
    # re_path(r'.*/inc-result', views.inc_result, name="inc-result"),
    # re_path(r'.*/dec-result', views.dec_result, name="dec-result")
]