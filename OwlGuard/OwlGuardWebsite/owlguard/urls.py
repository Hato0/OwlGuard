from django.urls import path, include
from . import views



urlpatterns = [
    path('', views.index, name="owlguard"),
    path('add-rule', views.add_rule, name="add-rule")
]
