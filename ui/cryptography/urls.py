from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('file', views.file, name="file-encode"),
    path('text', views.text, name="text-encode"),
    path('downloads/<filename>/', views.download_file, name='download_file')
]