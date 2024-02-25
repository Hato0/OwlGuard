from django.urls import path, include
from . import views



urlpatterns = [
    path('', views.index, name="owlguard"),
    path('rules/create', views.add_rule, name="createRule"),
    path('rules', views.rules, name="rules"),
    path('rules/<int:id>', views.rulesById, name="rulesById"),
    path('rules/<int:id>/edit', views.edit_rule, name="editRule")
]
