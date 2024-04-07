import splunklib.client as client
from .alertConfiguration.splunk.config import initialConfig
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

def initiateCon(connectorInstance):
    if "://" in connectorInstance.url:
        HOST = ':'.join(connectorInstance.url.split(':',2)[:2]).split('//')[1]
        PORT = connectorInstance.url.split(':',2)[2] if len(connectorInstance.url.split(':',2)) > 2 else 8089
    else:
        HOST = connectorInstance.url.split(':')[0]
        PORT = connectorInstance.url.split(':')[1] if len(connectorInstance.url.split(':')) > 1 else 8089

    if PORT in ["443", "80", "8080", "8000", "8443"]:
        PORT = 8089

    service = client.connect(
    host=HOST,
    port=PORT,
    username=connectorInstance.api_client,
    password=connectorInstance.api_key,
    verify=connectorInstance.sslVerification
    )

    return service

def fetchDefinedRules(saved_searches):
    defined_rules = []
    for saved_search in saved_searches:
        defined_rules.append(saved_search.name)
    return defined_rules

def getSavedSearchDetails(service, saved_search_name):
    saved_search = service.saved_searches[saved_search_name]
    saved_search.refresh()
    properties = {
        "Name": saved_search.name,
        "Search Query": saved_search["search"],
        "Author": saved_search["access"]["owner"],
        "Is Scheduled": saved_search["is_scheduled"],
        "Disabled": saved_search["disabled"],
        "Severity": saved_search["alert.severity"]
    }
    return properties

def retrieveDefinedAlerts(service):
    saved_searches = service.saved_searches
    defined_rules = fetchDefinedRules(saved_searches)
    rulesProperties = []
    for rule in defined_rules:
            saved_search_details = getSavedSearchDetails(service, rule)
            if saved_search_details:
                if saved_search_details["Is Scheduled"] == "1":
                    rulesProperties.append(saved_search_details)
    return rulesProperties

def sigmaToSPL(path):
	splunkBackend = SplunkBackend()
	ruleToProceed = SigmaCollection.load_ruleset([path])
	ruleSPL = splunkBackend.convert(ruleToProceed)
	return ruleSPL[0]

def initiateAlarmActions(severity, status):
    alertActionActionnable = {
    "alert.expires": "48h",
    "disabled": status,
    "action.ssg_mobile_alert.param.alert_severity": severity,
	"alert.managedBy": "",  #Can be empty
	"alert.severity": severity,
	"alert.suppress": "0",
	"alert.suppress.fields": "", #Can be empty
	"alert.suppress.period": "" #Can be empty
    }
    alertAction = {
	**alertActionActionnable, **initialConfig
    }
    return alertAction

def createAlert(service, savedSearchName, searchDescription, searchQuery, alertAction):
	try: 
		savedSearch = service.saved_searches.create(
			app="search",
			name=savedSearchName,
			description=searchDescription, 
			search=searchQuery
			)
		savedSearch.update(
			**alertAction
		)
		return True
	except:
		return False
     
def updateAlert(service, savedSearchName, searchDescription, searchQuery, alertAction):
    try:
        mysavedsearch = service.saved_searches[savedSearchName]
        kwargs = {"description": searchDescription,
                "search":searchQuery,
                **alertAction}
        mysavedsearch.update(**kwargs).refresh()
        return True
    except:
	    return False