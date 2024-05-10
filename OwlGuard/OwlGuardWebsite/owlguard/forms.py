from django import forms
from .models import Rule, Connector, StatusByRule, SPLByRule, InvestigationProcess

class UploadYAMLForm(forms.Form):
    yaml_files = forms.FileField(label='Select YAML file(s)', required=False)

class RuleForm(forms.ModelForm):
    class Meta:
        model = Rule
        fields = ('title', 'description', 'references', 'tags', 'logsource_id', 'detection', 'falsepositives', 'level')
        widgets = {
            'references': forms.TextInput(attrs={'placeholder': 'Enter references separated by comma'}),
            'detection': forms.TextInput(attrs={'placeholder': 'Enter detection data in JSON format'}),
            'level': forms.TextInput(attrs={'placeholder': 'Enter either critical, high, medium or low'})
        }

    def __init__(self, *args, **kwargs):
        super(RuleForm, self).__init__(*args, **kwargs)
        self.fields['title'].widget.attrs.update({'class': 'form-input'})
        
class ConnectorForm(forms.ModelForm):
    class Meta:
        model = Connector
        types = {'placeholder': '-- Chose from the available list --', 'splunk': 'Splunk'}
        fields = ('title', 'type', 'status', 'active', 'sslVerification', 'url', 'api_client', 'api_key')
        widgets = {
            'type': forms.Select(choices=types),
            'api_key': forms.PasswordInput()
        }
    def __init__(self, *args, **kwargs):
        super(ConnectorForm, self).__init__(*args, **kwargs)        

class RuleAssociationForm(forms.ModelForm):

    id_pk = forms.IntegerField(disabled=True, widget=forms.HiddenInput())
    class Meta:
        model = Rule
        fields = ('id', 'title', 'associatedConnector')
        widgets = {
            'associatedConnector': forms.CheckboxSelectMultiple()
        }

    def __init__(self, *args, **kwargs):
        super(RuleAssociationForm, self).__init__(*args, **kwargs)
        self.fields['title'].required = False
        self.fields['associatedConnector'].widget.attrs.update({'class': 'id_status'})

class RuleStatusForm(forms.ModelForm):
    class Meta:
        model = StatusByRule
        fields = ('rule', 'connector', 'status')
        widgets = {
            'status': forms.CheckboxInput()
        }

    def __init__(self, *args, **kwargs):
        super(RuleStatusForm, self).__init__(*args, **kwargs)
        self.fields['rule'].required = False
        self.fields['connector'].required = False
        self.fields['status'].widget.attrs.update({'class': 'id_status'})



    def clean(self):
        form_data = self.cleaned_data
        if form_data['status'] not in (True, False, "Unknown"):
            self._errors["status"] = ["Wrong status set"] # Will raise a error message
            del form_data['status']
        return form_data

class RuleSPLForm(forms.ModelForm):
    class Meta:
        model = SPLByRule
        fields = ('id', 'rule', 'spl')
        widgets = {
            'spl': forms.Textarea(attrs={'rows': 5, 'cols': 40,'style': 'height: auto;resize: vertical;'})
        }

    def __init__(self, *args, **kwargs):
        super(RuleSPLForm, self).__init__(*args, **kwargs)
        self.fields['rule'].required = False

class DocumentationForm(forms.ModelForm):
    class Meta:
        model = InvestigationProcess
        fields = ('title', 'goal', 'investigationsteps', 'remediationsteps', 'associatedRule')

    def __init__(self, *args, **kwargs):
        super(DocumentationForm, self).__init__(*args, **kwargs)
        self.fields['title'].widget.attrs.update({'class': 'form-input'})