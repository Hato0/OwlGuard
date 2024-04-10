from django.utils import timezone
from apscheduler.schedulers.background import BackgroundScheduler
from .models import Rule, Connector, Tags, StatusByRule, SPLByRule
from django.shortcuts import get_object_or_404
from .utils_splunk import *
from .utils import *
import uuid


def start():
    scheduler = BackgroundScheduler()
    # scheduler.add_job(updateDetections, 'interval', seconds=30)
    # scheduler.add_job(pushUpdates, 'interval', minutes=15)
    scheduler.start()

def updateDetections():
    try:
        connectors = Connector.objects.filter(status=True)
        definedRules = Rule.objects.all()
        for connectorInstance in connectors:
            if connectorInstance.type == "splunk":
                service = initiateCon(connectorInstance)
                alreadyDefinedRules = retrieveDefinedAlerts(service)
                levelTable = {'1': 'low', '2': 'low', '3': 'medium', '4': 'high', '5': 'critical'}
                for rule in alreadyDefinedRules:
                    if rule['Name'] in definedRules.values_list('title', flat=True):
                        modified = False
                        existingRule = Rule.objects.filter(title=rule['Name']).first()
                        if "/app/search/alert" not in existingRule['references']:
                            ruleURLFriendly = rule['Name'].replace(' ','%20')
                            existingRule.references= existingRule.references + [f"{connectorInstance.url}/app/search/alert?s=%2FservicesNS%2Fnobody%2Fsearch%2Fsaved%2Fsearches%2F{ruleURLFriendly}"]
                            modified = True
                        if existingRule.level != levelTable[rule['Severity']]:
                            existingRule.level =levelTable[rule['Severity']]
                            modified = True
                        updatedStatus = True if rule["Disabled"] == "0" else False
                        registeredStatus = StatusByRule.objects.filter(rule=existingRule, connector=connectorInstance).first()
                        if updatedStatus != registeredStatus.status:
                            registeredStatus.status = updatedStatus
                            status.save()
                            modified = True
                        connList = get_object_or_404(Connector, pk=connectorInstance.id)
                        if connList not in existingRule.associatedConnector:
                            existingRule.associatedConnector.set(existingRule.associatedConnector + [connList])
                            modified = True
                        registeredStatus = StatusByRule.objects.filter(rule=existingRule, connector=connectorInstance).first()
                        currentSPL = SPLByRule.objects.filter(rule=existingRule)
                        if currentSPL.spl != rule["Search Query"]:
                            currentSPL.spl = rule["Search Query"]
                            currentSPL.save()
                            modified = True
                        if modified:
                            saveRuleHistory(existingRule)
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
    except Exception as e:
        print(f"Error during execution {e}")

def pushUpdates():
    connectors = Connector.objects.filter(status=True)
    for connector in connectors:
        if connector.type == "splunk":
            service = initiateCon(connector)
            rulesToUpdate = Rule.objects.filter(toUpdate=True)
            print(f"[+] {len(rulesToUpdate)} to update ...")
            alreadyDefinedRules = retrieveDefinedAlerts(service)
            levelTable = {'1': 'low', '2': 'low', '3': 'medium', '4': 'high', '5': 'critical'}
            revLevelTable = {'low': '1', 'low': '2', 'medium': '3', 'high': '4', 'critical': '5'}
            for rule in rulesToUpdate:
                print(f"[+] Processing: {rule.title}")
                timeNow = timezone.now()
                query = sigmaToSPL(str(rule.raw)) if rule.raw else False
                status = StatusByRule.objects.filter(rule=rule,connector=connector).first()
                status = status.status
                existingData = False
                for elem in alreadyDefinedRules:
                    if elem['Name'] == rule.title:
                        existingData = elem
                if existingData:
                    spl = SPLByRule.objects.filter(rule=rule).first()
                    realUpdate = False
                    if query:
                        if query != existingData['Search Query']:
                            realUpdate = True
                            print("  [*] Query changed")
                    else:
                        if spl.spl != existingData['Search Query']:
                            realUpdate = True
                            print("  [*] Query changed")
                    if rule.level != levelTable[existingData['Severity']]:
                        realUpdate = True
                        print("  [*] Level changed")
                    comp = not bool(int(existingData['Disabled'])) if existingData['Disabled'] != "None" else False
                    if status != comp:
                        realUpdate = True
                        print("  [*] Status changed")
                    if realUpdate:
                        status = "0" if status else "1"
                        alertAction = initiateAlarmActions(revLevelTable[rule.level], status)
                        if query:
                            res = updateAlert(service, rule.title, rule.description + f"\n\n\n Updated by OwlGuard ({timeNow})" , query, alertAction)
                        else:
                            res = updateAlert(service, rule.title, rule.description + f"\n\n\n Updated by OwlGuard ({timeNow})" , spl.spl, alertAction)
                else:
                    print("  [*] Rule not yet onboarded, creating it ...")
                    savedSearchName = rule.title
                    searchQuery = query
                    searchDescription = rule.description + f"\n\n\n Updated by OwlGuard ({timeNow})"
                    ruleQuery = SPLByRule.objects.create(
                                        rule=rule,
                                        spl=query
                                        )
                    ruleQuery.save()
                    status = "0" if status else "1"
                    alertAction = initiateAlarmActions(revLevelTable[rule.level], status)
                    res = createAlert(service, savedSearchName, searchDescription, searchQuery, alertAction)
                if res:
                    print("  [*] Successfully updated")
                    rule.toUpdate = False
                    rule.save()
                else: 
                    print("  [-] Error during creation")