from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Rule, TestingScript, Connector, Reminders, Tags, Logsource, StatusByRule, SPLByRule, HistoryByRule, InvestigationProcess, HistoryByInvestigationProcess, TestingScript, HistoryByTestingScript
from django.db.models import Count, Q
from django.forms import formset_factory
from django.utils import timezone
from .forms import UploadYAMLForm, RuleForm, ConnectorForm, RuleAssociationForm, RuleStatusForm, RuleSPLForm, DocumentationForm, ScriptForm
from datetime import datetime
from django.contrib import messages
import yaml, json, uuid
from .utils_splunk import *
from .utils import *
import splunklib.client as client
import splunklib.results as results

# Rules views
@login_required
def index(request):
    current_user = request.user
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        ruleEnabled = Rule.objects.filter(associatedConnector=currentConnector, statusbyrule__connector=currentConnector, statusbyrule__status=True)
        ruleDisabled = Rule.objects.filter(associatedConnector=currentConnector).exclude(statusbyrule__connector=currentConnector, statusbyrule__status=True)        
        rulesDocumentationAnnotate = Rule.objects.annotate(investigation_process_id__count=Count('investigation_process_id'),
            status=Count('statusbyrule', filter=Q(statusbyrule__connector=currentConnector, statusbyrule__status=True))).filter(associatedConnector=currentConnector)
        testingScriptAvailable = TestingScript.objects.all()
        taskReminder = Reminders.objects.filter(user_id__exact=current_user.id)
        notificationUser = Reminders.objects.filter(user_id__exact=current_user.id)
        connectorEnable = Connector.objects.all()
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        ruleEnabled = Rule.objects.filter(statusbyrule__status=True)
        ruleDisabled = Rule.objects.all().exclude(statusbyrule__status=True)    
        rulesDocumentationAnnotate = Rule.objects.annotate(investigation_process_id__count=Count('investigation_process_id'),
            status=Count('statusbyrule', filter=Q(statusbyrule__status=True)))
        testingScriptAvailable = TestingScript.objects.all()
        taskReminder = Reminders.objects.filter(user_id__exact=current_user.id)
        notificationUser = Reminders.objects.filter(user_id__exact=current_user.id)
        connectorEnable = Connector.objects.all()
        allConnector = Connector.objects.all()
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
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/index.html', templateArgs)

@login_required
def rules(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
        ruleAll = Rule.objects.filter(associatedConnector=currentConnector).prefetch_related('tags').annotate(status=Count('statusbyrule', filter=Q(statusbyrule__connector=currentConnector)))
    else:
        allConnector = Connector.objects.all()
        ruleAll = Rule.objects.all().prefetch_related('tags', 'statusbyrule_set')
    extractedRuleInfo = []
    for item in ruleAll:
        tagInfo = list(item.tags.values('id', 'title'))
        statusFetch = list(item.statusbyrule_set.values('id', 'connector', 'status'))
        statusInfo = []
        for elem in statusFetch:
            connectorTitle = Connector.objects.filter(id=elem['connector']).first()
            statusInfo.append({'title': connectorTitle.title, 'status': elem['status']})
        extractedRuleInfo.append({
            'id': item.id,
            'title': item.title,
            'import_at': item.import_at.strftime("%b. %d, %Y"),
            'status': statusInfo,
            'author': item.author,
            'description': item.description,
            'tags': tagInfo,
            'toUpdate': item.toUpdate
        })
    templateArgs = {"extractedRuleInfo": extractedRuleInfo}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/rules.html', templateArgs)

@login_required
def rulesById(request, id):
    rule = get_object_or_404(Rule, pk=id)
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
        rule.status = StatusByRule.objects.filter(connector=currentConnector, rule=rule.id).first()
    else:
        allConnector = Connector.objects.all()
        rule.status = StatusByRule.objects.filter(rule=rule.id).first()
    rule.import_at=rule.import_at.strftime("%b. %d, %Y")
    rule.creation_date=rule.creation_date.strftime("%b. %d, %Y")
    if rule.modified:
        rule.modified=rule.modified.strftime("%b. %d, %Y")
    ruleByConnectorType = SPLByRule.objects.filter(rule=rule)
    for SPL in ruleByConnectorType:
        rule.spl = SPL.spl.split('\n')
        rule.SPLid = SPL.id
    templateArgs = {'rule_details': rule}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/rules_details.html', templateArgs)

@login_required
def add_rule(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
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
                    description=rule_data['description'],
                    references=rule_data.get('references', []),
                    author=rule_data['author'],
                    creation_date=datetime.strptime(rule_data['date'], '%Y/%m/%d'),
                    detection=rule_data['detection'],
                    falsepositives=', '.join(rule_data.get('falsepositives', [])),
                    level=rule_data['level'],
                )
                if currentConnector:
                    status = StatusByRule.objects.create(
                    rule=rule,
                    connector=currentConnector,
                    status=False)
                    status.save()
                    connList = get_object_or_404(Connector, pk=currentConnector.id)
                    rule.associatedConnector.set([connList])
                rule.tags.set(tagList)
                rule.logsource_id.set(lsList)
                rule.raw = yaml_file
                rule.toUpdate = True
                rule.save()
            return redirect('rules')
    else:
        form = UploadYAMLForm()
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/add_rule.html', templateArgs)


@login_required
def edit_rule(request, id):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    rule = Rule.objects.get(id=id)
    if request.method == 'POST':
        form = RuleForm(request.POST, instance=rule)
        if form.is_valid():
            res = saveRuleHistory(rule)
            if rule.raw:
                with open(str(rule.raw), 'r') as file:
                    data = yaml.safe_load(file)
            tagToUpdate, logSourceToUpdate, references, detectionToUpdate, conditionTemp = "", "", "", "", ""
            sortedTags = sorted(form.data.getlist('tags[]'))
            sortedLogSource = sorted(form.data.getlist('logsource_id[]'))
            for tag in sortedTags:
                   tempObj = Tags.objects.filter(pk=tag).first()
                   tagToUpdate += f"    - {tempObj.title}\n"
            for logSource in sortedLogSource:
                   tempObj = Logsource.objects.filter(pk=logSource).first()
                   logSourceToUpdate += f"    {tempObj.type}: {tempObj.title}\n"
            for reference in form.data.getlist('references'):
                reference = reference.split(',')
                for link in reference:
                    references += f"    - {link.strip()}\n"
            detectionData = json.loads(form.data.get('detection'))
            for param, value in detectionData.items():
                if param == "condition":
                    conditionTemp = value
                else:
                    key = list(value.keys())
                    if type(value[key[0]]) is not list:
                        detectionToUpdate += f"    {param}:\n        {key[0]}: '{value[key[0]]}'\n"
                    else:
                        detectionToUpdate += f"    {param}:\n        {key[0]}:\n"
                        for elem in value[key[0]]:
                            detectionToUpdate += f"            - '{elem}'\n"
            detectionToUpdate += f"    condition: {conditionTemp}\n"
            yamlReWrite = f"""title: {form.data.get('title')}
id: {rule.reference_id}
status: {data['status']}
description: {form.data.get('description')}
references: \n    {references.strip()}
author: {data['author']}
date: {data['date']}
modified: {timezone.now().isoformat().split('.')[0]}
tags:\n    {tagToUpdate.strip()}
logsource:\n    {logSourceToUpdate.strip()}
detection:\n    {detectionToUpdate.strip()}
falsepositives:\n    - {form.data.get('falsepositives')}
level: {form.data.get('level')}"""
            if rule.raw:
                with open(str(rule.raw), 'w') as file:
                    file.writelines(yamlReWrite)
            form.save()
            rule.modified = timezone.now().isoformat()
            rule.modified_by = request.user
            rule.tags.set(form.data.getlist('tags[]'))
            rule.logsource_id.set(form.data.getlist('logsource_id[]'))
            rule.toUpdate = True
            rule.save()
            return redirect('rulesById', id)
    else:
        form = RuleForm(instance=rule)
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/edit_rule.html', templateArgs)

@login_required
def editRuleSPL(request, id):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    rule = SPLByRule.objects.get(id=id)
    ruleData = Rule.objects.get(id=rule.rule.id)
    if request.method == 'POST':
        form = RuleSPLForm(request.POST, instance=rule)
        if form.is_valid():
            res = saveRuleHistory(rule.rule)
            rule.spl = request.POST.get('spl')
            rule.rule = rule.rule
            ruleData.modified = timezone.now().isoformat()
            ruleData.modified_by = request.user
            rule.toUpdate = True
            ruleData.save()
            rule.save()
            return redirect('rulesById', rule.rule.id)
    else:
        form = RuleSPLForm(instance=rule)
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/editRuleSPL.html', templateArgs)

@login_required
def delRuleById(request, id):
    rule = get_object_or_404(Rule, pk=id)
    rule.delete()
    return redirect('rules')  

def ruleHistoryById(request, id):
    rule = get_object_or_404(Rule, pk=id)
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
        rule.status = StatusByRule.objects.filter(connector=currentConnector, rule=rule.id).first()
    else:
        allConnector = Connector.objects.all()
        rule.status = StatusByRule.objects.filter(rule=rule.id).first()
    ruleByConnectorType = SPLByRule.objects.filter(rule=rule)
    for SPL in ruleByConnectorType:
        rule.spl = SPL.spl.split('\n')
    templateArgs = {'rule_details': rule}
    allHistory = HistoryByRule.objects.filter(rule=rule)
    cnt=0
    templateArgs['historicData'] = []
    for history in allHistory:
        ruleByConnectorType = SPLByRule.objects.filter(rule=rule)
        for SPL in ruleByConnectorType:
            history.spl = SPL.spl.split('\n')
        templateArgs['historicData'].append([f"history_{cnt}", history])
        cnt += 1
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/rules_history.html', templateArgs)

# Connector views

@login_required
def connectors(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    connectorAll = Connector.objects.all()
    extractedConnectorInfo = []
    for item in connectorAll:
        extractedConnectorInfo.append({
            'id': item.id,
            'title': item.title,
            'status': item.status,
            'active': item.active,
            'type': item.type,
            'url': item.url,
        })
    templateArgs = {"extractedConnectorInfo": extractedConnectorInfo}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/connectors/connectors.html', templateArgs)

@login_required
def add_connector(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    if request.method == 'POST':
        form = ConnectorForm(request.POST)
        if form.is_valid():
            connectorInstance = form.save(commit=False)
            currentConnector = Connector.objects.filter(active__exact="1").first()
            if currentConnector and connectorInstance.active:
                currentConnector.active = False
                currentConnector.save()
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
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/connectors/add_connector.html', templateArgs)

@login_required
def edit_connector(request, id):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    connector = Connector.objects.get(id=id)
    if request.method == 'POST':
        form = ConnectorForm(request.POST, instance=connector)
        if form.is_valid():
            connectorInstance = form.save(commit=False)
            currentConnector = Connector.objects.filter(active__exact="1").first()
            if currentConnector and connectorInstance.active:
                currentConnector.active = False
                currentConnector.save()
            testResult = testConnection(connectorInstance)
            if testResult == True:
                connectorInstance.save()
                return redirect('connectors')
            else:
                messages.error(request, f"Connection test failed. Please check your connection settings: {testResult}")
    else:
        form = ConnectorForm(instance=connector)
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/connectors/add_connector.html', templateArgs)

@login_required
def connectorById(request, id):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    connector = get_object_or_404(Connector, pk=id)
    connector.api_key = connector.masked_api_key()
    templateArgs = {'connector_details': connector}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/connectors/connector_details.html', templateArgs)

@login_required
def delConnectorById(request, id):
    connector = get_object_or_404(Connector, pk=id)
    connector.delete()
    return redirect('connectors')  

#Rule Status and Association Management
@login_required
def ruleManagementAssociation(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    connectors = Connector.objects.all()
    rules = Rule.objects.all()
    GlobalRuleAssociationFormSet = formset_factory(RuleAssociationForm, extra=0)
    initial_data = []
    for rule in rules:
        data = {
            'id': rule.id,
            'title': rule.title,
            'id_pk': rule.id,
        }
        if rule.associatedConnector.exists():
            data['associatedConnector'] = rule.associatedConnector.all()
        initial_data.append(data)
    if request.method == 'POST':
        formset = GlobalRuleAssociationFormSet(request.POST, initial=initial_data)
        if formset.is_valid():
            for form in formset:
                ruleID = form.cleaned_data['id_pk']
                associatedConnectorValues = form.cleaned_data.get('associatedConnector', [])
                rule = Rule.objects.filter(id__exact=ruleID).prefetch_related('associatedConnector').get()
                modified = False
                compareListConn = list(connectAssoc.id for connectAssoc in associatedConnectorValues)
                for connector in rule.associatedConnector.values('id'):  
                    print(compareListConn)  
                    print(connector['id'])           
                    if connector['id'] not in compareListConn:
                        modified = True
                if len(rule.associatedConnector.values('id')) != len(compareListConn):
                    modified = True
                if modified: 
                    res = saveRuleHistory(rule)
                    rule.associatedConnector.set(associatedConnectorValues)
                    rule.modified = timezone.now().isoformat()
                    rule.modified_by = request.user
                    rule.toUpdate = True
                    rule.save()
            return redirect('rules')
    else:
        formset = GlobalRuleAssociationFormSet(initial=initial_data)    
    templateArgs = {'formset': formset}
    templateArgs['connectors'] = connectors
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/management_rule_association.html', templateArgs)

@login_required
def ruleManagementStatus(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    connectors = Connector.objects.all()
    rules = Rule.objects.all()
    GlobalRuleStatusFormSet = formset_factory(RuleStatusForm, extra=0)
    initial_data = []
    rules = Rule.objects.all()
    iter = 0
    for rule in rules:
        for connector in connectors:
            seen = False
            if len(rule.associatedConnector.values()):
                for association in rule.associatedConnector.values():
                    if str(connector) ==  association['title']:    
                        seen = True
                        statusData = StatusByRule.objects.filter(connector=connector, rule=rule).first()
                        if statusData:
                            data = {
                                'id': statusData.id,
                                'rule': statusData.rule,
                                'connector': statusData.connector,
                                'status': statusData.status
                                }
                        else:
                            data = {
                                'id': len(rules)*2+iter,
                                'rule': rule,
                                'connector': connector,
                                'status': False
                                }
                            iter += 1
                        initial_data.append(data)
                if not seen:
                    data = {
                            'id': len(rules)*2+iter,
                            'rule': rule,
                            'connector': connector,
                            'status': None
                            }
                    iter += 1
                    initial_data.append(data)
            else:
                data = {
                    'id': len(rules)*2+iter,
                    'rule': rule,
                    'connector': connector,
                    'status': None
                    }
                iter += 1
                initial_data.append(data)
    if request.method == 'POST':
        formset = GlobalRuleStatusFormSet(request.POST, initial=initial_data)
        if formset.is_valid():
            for form in formset:
                isExisting = StatusByRule.objects.filter(rule=form.cleaned_data['rule'], connector=form.cleaned_data['connector']).first()
                if isExisting:
                    if isExisting.status != form.cleaned_data['status']:
                        res = saveRuleHistory(form.cleaned_data['rule'])
                        form.cleaned_data['rule'].modified_by = request.user
                        form.cleaned_data['rule'].modified = timezone.now().isoformat()
                        form.cleaned_data['rule'].toUpdate = True
                        form.cleaned_data['rule'].save()
                    isExisting.status = form.cleaned_data['status']
                    isExisting.save()
                else:
                    if form.cleaned_data['connector'] is not None and form.cleaned_data['rule'] is not None:
                        newStatusByRule = StatusByRule.objects.create(
                                            rule=form.cleaned_data['rule'],
                                            connector=form.cleaned_data['connector'],
                                            status=form.cleaned_data['status']
                                        )
                        newStatusByRule.save()
                        form.cleaned_data['rule'].modified_by = request.user
                        form.cleaned_data['rule'].modified = timezone.now().isoformat()
                        form.cleaned_data['rule'].toUpdate = True
                        form.cleaned_data['rule'].save()
                        res = saveRuleHistory(form.cleaned_data['rule'])
            return redirect('rules')
    else:
        formset = GlobalRuleStatusFormSet(initial=initial_data)    
    templateArgs = {'formset': formset}
    templateArgs['connectors'] = connectors
    templateArgs['rules'] = rules
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/rules/management_rule_status.html', templateArgs)

# Integration specific
def testConnection(connectorInstance):
    try:
        if connectorInstance.type == "splunk":
            service = initiateCon(connectorInstance)

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
    if connectorInstance.type == "splunk":
        service = initiateCon(connectorInstance)
        alreadyDefinedRules = retrieveDefinedAlerts(service)
        definedRules = Rule.objects.all()
        levelTable = {'1': 'low', '2': 'low', '3': 'medium', '4': 'high', '5': 'critical'}
        for rule in alreadyDefinedRules:
            if rule['Name'] in definedRules.values_list('title', flat=True):
                modified = False
                existingRule = Rule.objects.filter(title=rule['Name']).first()
                if "/app/search/alert" not in existingRule.references:
                    existingRule.references= existingRule.references + [f"{connectorInstance.url}/app/search/alert?s=%2FservicesNS%2Fnobody%2Fsearch%2Fsaved%2Fsearches%2F{rule['Name']}"]
                    modified = True
                if existingRule.level != levelTable[rule['Severity']]:
                    existingRule.level =levelTable[rule['Severity']]
                    modified = True
                updatedStatus = True if rule["Disabled"] == "0" else False
                registeredStatus = StatusByRule.objects.filter(rule=existingRule, connector=connectorInstance).first()
                if registeredStatus:
                    if updatedStatus != registeredStatus.status:
                        registeredStatus.status = updatedStatus
                        modified = True
                else:
                    status = StatusByRule.objects.create(
                        rule=existingRule,
                        connector=connectorInstance,
                        status=updatedStatus)
                status.save()
                connList = get_object_or_404(Connector, pk=connectorInstance.id)
                if connList not in existingRule.associatedConnector.all():
                    currentConn = existingRule.associatedConnector.all().values_list('id', flat=True)
                    connCList = []
                    for elem in currentConn:
                        connCList.append(elem)
                    existingRule.associatedConnector.set(connCList + [connList])
                    modified = True
                registeredStatus = StatusByRule.objects.filter(rule=existingRule, connector=connectorInstance).first()
                currentSPL = SPLByRule.objects.filter(rule=existingRule).first()
                if currentSPL:
                    if currentSPL.spl != rule["Search Query"]:
                        currentSPL.spl = rule["Search Query"]
                        currentSPL.save()
                        modified = True
                else:
                    query = SPLByRule.objects.create(
                        rule=existingRule,
                        spl=rule["Search Query"]
                        )
                    query.save()
                if modified:
                    existingRule.modified = timezone.now().isoformat()
                existingRule.save()
            else:
                newRule = Rule.objects.create(
                        title=rule['Name'],
                        reference_id=str(uuid.uuid4()),
                        description=f"Automatically imported. Imported from connector: {connectorInstance.title}.",
                        author=rule['Author'],
                        references=[f"{connectorInstance.url}/app/search/alert?s=%2FservicesNS%2Fnobody%2Fsearch%2Fsaved%2Fsearches%2F{rule['Name']}"],
                        creation_date=timezone.now().isoformat(),
                        detection={'detail': 'Imported from connector, SIGMA format not available.'},
                        falsepositives="Unknown",
                        level=levelTable[rule['Severity']],
                    )
                statusToRegister = True if rule["Disabled"] == "0" else False
                status = StatusByRule.objects.create(
                        rule=newRule,
                        connector=connectorInstance,
                        status=statusToRegister)
                status.save()
                connList = get_object_or_404(Connector, pk=connectorInstance.id)
                newRule.associatedConnector.set([connList])
                query = SPLByRule.objects.create(
                        rule=newRule,
                        spl=rule["Search Query"]
                        )
                query.save()
                tagIDs = []
                tagInfoTemp = Tags.objects.filter(title__exact="auto_imported")
                if len(tagInfoTemp) == 0:
                    new_tag = Tags.objects.create(
                        title="auto_imported",
                        description='Automatically generated'
                    )
                    tagIDs.append(new_tag.id)
                    new_tag.save()
                else:
                    for tag in tagInfoTemp:
                        tagIDs.append(tag.id)
                tagList = Tags.objects.filter(pk__in=tagIDs)
                newRule.tags.set(tagList)
                newRule.save()
    return True

@login_required
def handleConnectorChange(request):
    if request.method == 'POST':
        selectedConnector = request.POST.get('activeConnector')
        if selectedConnector != "None":
            connector = get_object_or_404(Connector, title=selectedConnector)
        currentConnector = Connector.objects.filter(active__exact="1").first()
        if currentConnector:
            currentConnector.active = False
            currentConnector.save()
            if selectedConnector != "None":
                connector.active = True
                connector.save()
        else:
            connector.active = True
            connector.save()
    redirectPage = request.POST.get('previousPage')
    return redirect(redirectPage)

#Documentation
@login_required
def documentation(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    documentationAll = InvestigationProcess.objects.all().prefetch_related('associatedRule')
    extractedDocumentInfo = []
    for item in documentationAll:
        ruleInfo = list(item.associatedRule.values('id', 'title'))
        extractedDocumentInfo.append({
            'id': item.id,
            'title': item.title,
            'creation_date': item.creation_date.strftime("%b. %d, %Y"),
            'author': item.author,
            'rules': ruleInfo,
            'lastModified': item.modified,
            'lastModifiedBy': item.modified_by
        })
    templateArgs = {"extractedDocumentInfo": extractedDocumentInfo}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/documentations/documentations.html', templateArgs)

def add_documentation(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    if request.method == 'POST':
        form = DocumentationForm(request.POST)
        if form.is_valid():
            instance = form.save(commit=False)
            instance.creation_date = timezone.now()
            instance.author = request.user
            instance.save()
            instance.associatedRule.set(form.data.getlist('associatedRule[]'))
            instance.save()
            return redirect('documentations')
    else:
        form = DocumentationForm()
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/documentations/add_documentation.html', templateArgs)

@login_required
def edit_documentation(request, id):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    documentation = InvestigationProcess.objects.get(id=id)
    if request.method == 'POST':
        form = DocumentationForm(request.POST, instance=documentation)
        if form.is_valid():
            res = saveDocuHistory(documentation)
            instance = form.save(commit=False)
            instance.modified = timezone.now()
            instance.modified_by = request.user
            instance.save()
            instance.associatedRule.set(form.data.getlist('associatedRule[]'))
            instance.save()
            return redirect('docuById', id)
    else:
        form = DocumentationForm(instance=documentation)
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/documentations/edit_documentation.html', templateArgs)

def docuById(request, id):
    documentation = get_object_or_404(InvestigationProcess, pk=id)
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    documentation.creation_date=documentation.creation_date.strftime("%b. %d, %Y")
    if documentation.modified:
        documentation.modified=documentation.modified.strftime("%b. %d, %Y")
    templateArgs = {'documentation_details': documentation}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/documentations/documentation_details.html', templateArgs)

@login_required
def delDocuById(request, id):
    docu = get_object_or_404(InvestigationProcess, pk=id)
    docu.delete()
    return redirect('documentations')  

@login_required
def docuHistoryById(request, id):
    documentation = get_object_or_404(InvestigationProcess, pk=id)
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    templateArgs = {'documentation_details': documentation}
    allHistory = HistoryByInvestigationProcess.objects.filter(investigationProcess=documentation)
    cnt=0
    templateArgs['historicData'] = []
    for history in allHistory:
        templateArgs['historicData'].append([f"history_{cnt}", history])
        cnt += 1
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/documentations/documentation_history.html', templateArgs)

#Script
@login_required
def script(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    documentationAll = TestingScript.objects.all().prefetch_related('associatedRule')
    extractedScriptInfo = []
    for item in documentationAll:
        ruleInfo = list(item.associatedRule.values('id', 'title'))
        extractedScriptInfo.append({
            'id': item.id,
            'title': item.title,
            'creation_date': item.creation_date.strftime("%b. %d, %Y"),
            'author': item.author,
            'rules': ruleInfo,
            'lastModified': item.modified,
            'lastModifiedBy': item.modified_by
        })
    templateArgs = {"extractedScriptInfo": extractedScriptInfo}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/scripts/scripts.html', templateArgs)

def add_script(request):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    if request.method == 'POST':
        form = ScriptForm(request.POST)
        if form.is_valid():
            instance = form.save(commit=False)
            instance.creation_date = timezone.now()
            instance.author = request.user
            instance.save()
            instance.associatedRule.set(form.data.getlist('associatedRule[]'))
            instance.save()
            return redirect('scripts')
    else:
        form = ScriptForm()
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/scripts/add_scripts.html', templateArgs)

@login_required
def edit_script(request, id):
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    script = TestingScript.objects.get(id=id)
    if request.method == 'POST':
        form = ScriptForm(request.POST, instance=script)
        if form.is_valid():
            res = saveScriptHistory(script)
            instance = form.save(commit=False)
            instance.modified = timezone.now()
            instance.modified_by = request.user
            instance.save()
            instance.associatedRule.set(form.data.getlist('associatedRule[]'))
            instance.save()
            return redirect('scriptById', id)
    else:
        form = ScriptForm(instance=script)
    templateArgs = {'form': form}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/scripts/edit_scripts.html', templateArgs)

def scriptById(request, id):
    script = get_object_or_404(TestingScript, pk=id)
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    script.creation_date=script.creation_date.strftime("%b. %d, %Y")
    if script.modified:
        script.modified=script.modified.strftime("%b. %d, %Y")
    templateArgs = {'script_details': script}
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/scripts/scripts_details.html', templateArgs)

@login_required
def delScriptById(request, id):
    script = get_object_or_404(TestingScript, pk=id)
    script.delete()
    return redirect('scripts')  

@login_required
def scriptHistoryById(request, id):
    script = get_object_or_404(TestingScript, pk=id)
    currentConnector = Connector.objects.filter(active=True).first()
    if currentConnector:
        allConnector = Connector.objects.all().exclude(id=currentConnector.id)
    else:
        allConnector = Connector.objects.all()
    templateArgs = {'script_details': script}
    allHistory = HistoryByTestingScript.objects.filter(testingScript=script)
    cnt=0
    templateArgs['historicData'] = []
    for history in allHistory:
        templateArgs['historicData'].append([f"history_{cnt}", history])
        cnt += 1
    templateArgs["currentConnector"] = currentConnector
    templateArgs["allConnector"] = allConnector
    return render(request, 'owlguard/scripts/scripts_history.html', templateArgs)

# Here if you want to test something using the /test endpoint
def test(request):
    pass

