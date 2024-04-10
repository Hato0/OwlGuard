from .models import Rule, StatusByRule, HistoryByRule, SPLByRule

def saveRuleHistory(rule):
    try:
        SPL = SPLByRule.objects.filter(rule=rule).first()
        rules = Rule.objects.filter(id=rule.id).all().prefetch_related('tags', 'logsource_id', 'testing_script_id', 'investigation_process_id', 'associatedConnector')
        for ruleData in rules:
            Status = StatusByRule.objects.filter(rule=rule).all()
            ruleHistory = HistoryByRule.objects.create(
                                rule = ruleData,
                                title = ruleData.title,
                                reference_id = ruleData.reference_id,
                                description = ruleData.description,
                                references = ruleData.references,
                                author = ruleData.author,
                                import_at = ruleData.import_at,
                                modified = ruleData.modified,
                                modified_by = ruleData.modified_by,
                                detection = ruleData.detection,
                                falsepositives = ruleData.falsepositives,
                                level = ruleData.level,
                            )    
            tags = [] 
            for item in ruleData.tags.values('id'):
                tags.append(item['id'])
            logsource_id = [] 
            for item in ruleData.logsource_id.values('id'):
                logsource_id.append(item['id'])
            testing_script_id = [] 
            for item in ruleData.testing_script_id.values('id'):
                testing_script_id.append(item['id'])
            investigation_process_id = [] 
            for item in ruleData.investigation_process_id.values('id'):
                investigation_process_id.append(item['id'])
            associatedConnector = [] 
            for item in ruleData.associatedConnector.values('id'):
                associatedConnector.append(item['id'])
            ruleHistory.tags.set(tags)
            ruleHistory.logsource_id.set(logsource_id)
            ruleHistory.testing_script_id.set(testing_script_id)
            ruleHistory.investigation_process_id.set(investigation_process_id)
            ruleHistory.associatedConnector.set(associatedConnector)
            ruleHistory.SPL = SPL.spl if SPL else None
            statusToSave = []
            if Status:
                for status in Status:
                    statusToSave.append([status.connector, status.status])
            ruleHistory.status = statusToSave
            ruleHistory.save()
        return True
    except Exception as e:
        print(e)
        return False