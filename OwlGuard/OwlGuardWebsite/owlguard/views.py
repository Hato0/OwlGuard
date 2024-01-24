from django.shortcuts import render
from django.contrib.auth.decorators import login_required
# Create your views here.
@login_required
def index(request):
    return render(request, 'owlguard/index.html')

@login_required
def add_rule(request):
    return render(request, 'owlguard/add_rule.html')