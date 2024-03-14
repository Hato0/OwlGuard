from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Rule, TestingScript, Connector, Reminders, Tags, Logsource
from django.db.models import Count
from django.utils import timezone
from .forms import UploadYAMLForm, RuleForm, ConnectorForm
from datetime import datetime
from django.contrib import messages
import yaml, time
import splunklib.client as client
import splunklib.results as results

# Rules views
@login_required
def index(request):
    current_user = request.user
    ruleEnabled = Rule.objects.filter(status__exact="1")
    ruleDisabled = Rule.objects.filter(status__exact="0")
    rulesDocumentationAnnotate = Rule.objects.annotate(investigation_process_id__count=Count('investigation_process_id'))
    testingScriptAvailable = TestingScript.objects.all()
    taskReminder = Reminders.objects.filter(user_id__exact=current_user.id)
    notificationUser = Reminders.objects.filter(user_id__exact=current_user.id)
    connectorEnable = Connector.objects.all()
    today = timezone.now()
    undocumentedRule = []
    taskReminders = []
    for item in rulesDocumentationAnnotate:
        if item.investigation_process_id__count == 0: 

            undocumentedRule.append({'id': item.id, 'title': item.title, 'import_at': item.import_at.strftime("%b. %d, %Y"), 'status': item.status})
    for item in taskReminder:
        taskReminders.append({'id': item.id, 'title': item.title, 'due_at': item.due_at})
    templateArgs = {}
    templateArgs["cntRuleEnabled"] = len(ruleEnabled)
    templateArgs["cntRuleDisabled"] = len(ruleDisabled)
    templateArgs["cntTestingScript"] = len(testingScriptAvailable)
    templateArgs["cntConnector"] = len(connectorEnable)
    templateArgs["undocumentedRule"] = undocumentedRule
    templateArgs["taskReminders"] = taskReminders
    templateArgs["today"] = today
    templateArgs["notificationUser"] = notificationUser
    return render(request, 'owlguard/index.html', templateArgs)

@login_required
def rules(request):
    ruleAll = Rule.objects.all().prefetch_related('tags')  # Prefetch related tags to avoid N+1 queries
    extractedRuleInfo = []
    for item in ruleAll:
        tagInfo = list(item.tags.values('id', 'title'))  # Extract tag values
        extractedRuleInfo.append({
            'id': item.id,
            'title': item.title,
            'import_at': item.import_at.strftime("%b. %d, %Y"),
            'status': item.status,
            'author': item.author,
            'description': item.description,
            'tags': tagInfo
        })
    templateArgs = {"extractedRuleInfo": extractedRuleInfo}
    return render(request, 'owlguard/rules.html', templateArgs)

@login_required
def rulesById(request, id):
    rule = get_object_or_404(Rule, pk=id)
    rule.import_at=rule.import_at.strftime("%b. %d, %Y")
    rule.creation_date=rule.creation_date.strftime("%b. %d, %Y")
    if rule.modified:
        rule.modified=rule.modified.strftime("%b. %d, %Y")
    return render(request, 'owlguard/rules_details.html', {'rule_details': rule})

@login_required
def add_rule(request):
    if request.method == 'POST':
        form = UploadYAMLForm(request.POST, request.FILES)
        if form.is_valid():
            yaml_files = request.FILES.getlist('yaml_files')
            for yaml_file in yaml_files:
                rule_data = yaml.safe_load(yaml_file)
                tagIDs = []
                LSIDs = []
                for tag in rule_data.get('tags', []):
                    tagInfoTemp = Tags.objects.filter(title__exact=tag)
                    if len(tagInfoTemp) == 0:
                        new_tag = Tags.objects.create(
                            title=tag,
                            description='Automatically generated'
                        )
                        tagIDs.append(new_tag.id)
                        new_tag.save()
                    else:
                        for item in tagInfoTemp:
                            tagIDs.append(item.id)
                tagList = Tags.objects.filter(pk__in=tagIDs)
                for item in rule_data['logsource']:
                    logSourceInfoTemp = Logsource.objects.filter(title__exact=rule_data['logsource'][item])
                    if len(logSourceInfoTemp) == 0:
                        new_ls = Logsource.objects.create(
                            title=rule_data['logsource'][item],
                            type=item,
                            status=0
                        )
                        LSIDs.append(new_ls.id)
                        new_ls.save()
                    else:
                        for item in logSourceInfoTemp:
                            LSIDs.append(item.id)
                lsList = Logsource.objects.filter(pk__in=LSIDs)
                rule = Rule.objects.create(
                    title=rule_data['title'],
                    reference_id=rule_data.get('id'),
                    status=0,
                    description=rule_data['description'],
                    references=rule_data.get('references', []),
                    author=rule_data['author'],
                    creation_date=datetime.strptime(rule_data['date'], '%Y/%m/%d'),
                    detection=rule_data['detection'],
                    falsepositives=', '.join(rule_data.get('falsepositives', [])),
                    level=rule_data['level'],
                )
                rule.tags.set(tagList)
                rule.logsource_id.set(lsList)
                rule.save()
            return redirect('rules')
    else:
        form = UploadYAMLForm()
    return render(request, 'owlguard/add_rule.html', {'form': form})


@login_required
def edit_rule(request, id):
    rule = Rule.objects.get(id=id)
    if request.method == 'POST':
        form = RuleForm(request.POST, instance=rule)
        if form.is_valid():
            form.save()
            print(form.data)
            print(form.data.getlist('tags[]'))
            print(form.data.getlist('logsource_id[]'))
            rule.modified = timezone.now().isoformat()
            rule.modified_by = request.user
            rule.tags.set(form.data.getlist('tags[]'))
            rule.logsource_id.set(form.data.getlist('logsource_id[]'))
            rule.save()
            return redirect('rulesById', id)
    else:
        form = RuleForm(instance=rule)
    return render(request, 'owlguard/edit_rule.html', {'form': form})

# Connector views

@login_required
def connectors(request):
    connectorAll = Connector.objects.all()
    extractedConnectorInfo = []
    for item in connectorAll:
        extractedConnectorInfo.append({
            'id': item.id,
            'title': item.title,
            'status': item.status,
            'type': item.type,
            'sslVerification': item.sslVerification,
            'url': item.url,
            'api_client': item.api_client
        })
    templateArgs = {"extractedConnectorInfo": extractedConnectorInfo}
    return render(request, 'owlguard/connectors.html', templateArgs)

@login_required
def add_connector(request):
    if request.method == 'POST':
        form = ConnectorForm(request.POST)
        if form.is_valid():
            connectorInstance = form.save(commit=False)
            testResult = testConnection(connectorInstance)
            if testResult == True:
                connectorInstance.save()
                initialization = initiatedConnector(connectorInstance)
                if initialization:
                    return redirect('connectors')
                else:
                    messages.error(request, f"Error during initialization. Please check your settings: {testResult}")
            else:
                messages.error(request, f"Connection test failed. Please check your connection settings: {testResult}")
    else:
        form = ConnectorForm()
    return render(request, 'owlguard/add_connector.html', {'form': form})

@login_required
def edit_connector(request, id):
    connector = Connector.objects.get(id=id)
    if request.method == 'POST':
        form = ConnectorForm(request.POST, instance=connector)
        if form.is_valid():
            connectorInstance = form.save(commit=False)
            testResult = testConnection(connectorInstance)
            if testResult == True:
                connectorInstance.save()
                return redirect('connectors')
            else:
                messages.error(request, f"Connection test failed. Please check your connection settings: {testResult}")
    else:
        form = ConnectorForm(instance=connector)
    return render(request, 'owlguard/add_connector.html', {'form': form})

@login_required
def connectorById(request, id):
    connector = get_object_or_404(Connector, pk=id)
    connector.api_key = connector.masked_api_key()
    return render(request, 'owlguard/connector_details.html', {'connector_details': connector})

@login_required
def delConnectorById(request, id):
    connector = get_object_or_404(Connector, pk=id)
    connector.delete()
    return redirect('connectors')  

def testConnection(connectorInstance):
    try:
        if connectorInstance.type == "splunk":
            if "://" in connectorInstance.url:
                HOST = ':'.join(connectorInstance.url.split(':',2)[:2]).split('//')[1]
                PORT = connectorInstance.url.split(':',2)[2] if len(connectorInstance.url.split(':',2)) > 2 else 8089
            else:
                HOST = connectorInstance.url.split(':')[0]
                PORT = connectorInstance.url.split(':')[1] if len(connectorInstance.url.split(':')) > 1 else 8089

            service = client.connect(
            host=HOST,
            port=PORT,
            username=connectorInstance.api_client,
            password=connectorInstance.api_key,
            verify=connectorInstance.sslVerification
            )

            search_query = 'search * | head 1'
            kwargs_search = {"exec_mode": "normal"}
            job = service.jobs.create(search_query, **kwargs_search)
            while not job.is_ready():
                pass
            reader = results.JSONResultsReader(job.results(output_mode='json'))
            for result in reader:
                pass
            job.cancel()
            return True 
    except Exception as e:
        return e
    
def initiatedConnector(connectorInstance):
    time.sleep(500)
    return False