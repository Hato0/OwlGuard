from django import forms
from .models import Rule, Connector

class UploadYAMLForm(forms.Form):
    yaml_files = forms.FileField(label='Select YAML file(s)', required=False)

class RuleForm(forms.ModelForm):
    class Meta:
        model = Rule
        fields = ('title', 'status', 'description', 'references', 'tags', 'logsource_id', 'detection', 'falsepositives', 'level')
        widgets = {
            'references': forms.TextInput(attrs={'placeholder': 'Enter references separated by comma'}),
            'detection': forms.TextInput(attrs={'placeholder': 'Enter detection data in JSON format'}),
            'level': forms.TextInput(attrs={'placeholder': 'Enter either critical, high, medium or low'})
        }

    def __init__(self, *args, **kwargs):
        super(RuleForm, self).__init__(*args, **kwargs)
        self.fields['title'].widget.attrs.update({'class': 'form-input'})
        self.fields['status'].widget.attrs.update({'class': 'id_status'})
        
class ConnectorForm(forms.ModelForm):
    class Meta:
        model = Connector
        types = {'placeholder': '-- Chose from the available list --', 'splunk': 'Splunk'}
        fields = ('title', 'type', 'status', 'sslVerification', 'url', 'api_client', 'api_key')
        widgets = {
            'type': forms.Select(choices=types),
            'api_key': forms.PasswordInput()
        }
    def __init__(self, *args, **kwargs):
        super(ConnectorForm, self).__init__(*args, **kwargs)        