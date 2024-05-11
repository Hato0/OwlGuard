from django.urls import path, include
from . import views



urlpatterns = [
    path('', views.index, name="owlguard"),
    path('rules/create', views.add_rule, name="createRule"),
    path('rules', views.rules, name="rules"),
    path('rules/<int:id>', views.rulesById, name="rulesById"),
    path('rules/<int:id>/edit', views.edit_rule, name="editRule"),
    path('rules/<int:id>/editSPL', views.editRuleSPL, name="editRuleSPL"),
    path('rules/<int:id>/delete', views.delRuleById, name="delRuleById"),
    path('rules/<int:id>/history', views.ruleHistoryById, name="ruleHistoryById"),
    path('rules/management/association', views.ruleManagementAssociation, name="ruleManagementAssociation"),
    path('rules/management/status', views.ruleManagementStatus, name="ruleManagementStatus"),
    path('connectors', views.connectors, name="connectors"),
    path('connectors/create', views.add_connector, name="createConnector"),
    path('connectors/<int:id>', views.connectorById, name="connectorById"),
    path('connectors/<int:id>/edit', views.edit_connector, name="editConnector"),
    path('connectors/<int:id>/delete', views.delConnectorById, name="delConnectorById"),
    path('connectors/updateActive', views.handleConnectorChange, name="handleConnectorChange"),
    path('documentation', views.documentation, name="documentations"),
    path('documentation/create', views.add_documentation, name="createDocumentation"),
    path('documentation/<int:id>', views.docuById, name="docuById"),
    path('documentation/<int:id>/edit', views.edit_documentation, name="editDocumentation"),
    path('documentation/<int:id>/delete', views.delDocuById, name="delDocuById"),
    path('documentation/<int:id>/history', views.docuHistoryById, name="docuHistoryById"),
    path('script', views.script, name="scripts"),
    path('script/create', views.add_script, name="createScript"),
    path('script/<int:id>', views.scriptById, name="scriptById"),
    path('script/<int:id>/edit', views.edit_script, name="editScript"),
    path('script/<int:id>/delete', views.delScriptById, name="delScriptById"),
    path('script/<int:id>/history', views.scriptHistoryById, name="ScriptHistoryById"),
    #Uncomment if you need to enable the test endpoint
    #path('test', views.test, name="test"),

]
