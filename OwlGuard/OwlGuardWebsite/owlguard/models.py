from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models import User

# Create your models here.
class Notification(models.Model):
     title = models.CharField(max_length=255)
     detail = models.TextField()
     created_at = models.DateTimeField(auto_now_add=True)
     user_id = models.ForeignKey(User, on_delete=models.CASCADE)
     class Meta:
            ordering = ['id']
    
     def __str__(self):
        return self.title 
class Reminders(models.Model):
     title = models.CharField(max_length=255)
     detail = models.TextField()
     created_at = models.DateTimeField(auto_now_add=True)
     due_at = models.DateTimeField()
     user_id = models.ForeignKey(User, on_delete=models.CASCADE)
     class Meta:
            ordering = ['id']
    
     def __str__(self):
        return self.title 

class Tags(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
            ordering = ['id']
    
    def __str__(self):
        return self.title 
    
class TestingScript(models.Model):
    title = models.CharField(max_length=255)
    script = models.TextField()
    class Meta:
            ordering = ['id']
    
    def __str__(self):
        return self.title 
class Connector(models.Model):
    title = models.CharField(max_length=255)
    status = models.BooleanField()
    type = models.CharField(max_length=255)
    sslVerification = models.BooleanField()
    url = models.URLField(unique=True)
    api_client = models.CharField(max_length=255)
    api_key= models.CharField(max_length=255)
    active = models.BooleanField()

    def masked_api_key(self):
        return f"{self.api_key[:1]}{'*' * (len(self.api_key) - 2)}{self.api_key[-1:]}"
    class Meta:
            ordering = ['id']
    
    def __str__(self):
        return self.title 
class InvestigationProcess(models.Model):
    title = models.CharField(max_length=255)
    steps = ArrayField(models.TextField(blank=True))
    class Meta:
            ordering = ['id']
    
    def __str__(self):
        return self.title   
class Logsource(models.Model):
    title = models.CharField(max_length=255)
    type = models.CharField(max_length=255)
    status = models.BooleanField()
    class Meta:
            ordering = ['type']
    
    def __str__(self):
        return self.title   

class Rule(models.Model):
    title = models.CharField(max_length=255, unique=True)
    reference_id = models.CharField(max_length=40)
    description = models.TextField()
    references = ArrayField(models.CharField(max_length=200), blank=True)
    author = models.CharField(max_length=200)
    import_at = models.DateTimeField(auto_now_add=True)
    creation_date = models.DateTimeField()
    modified = models.DateTimeField(blank=True, null=True)
    modified_by = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True)
    tags = models.ManyToManyField(Tags, blank=True)
    logsource_id = models.ManyToManyField(Logsource, blank=True)
    detection = models.JSONField(blank=True, null=True)
    falsepositives = models.TextField()
    level = models.CharField(max_length=255)
    testing_script_id = models.ManyToManyField(TestingScript)
    investigation_process_id = models.ManyToManyField(InvestigationProcess)
    associatedConnector = models.ManyToManyField(Connector, related_name='rules', blank=True)
    toUpdate = models.BooleanField()
    raw = models.FileField(upload_to='owlguard/sigmaYAML/')
    class Meta:
            ordering = ['import_at']

    def __str__(self):
        return self.title            
    
class StatusByRule(models.Model):
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE)
    connector = models.ForeignKey(Connector, on_delete=models.CASCADE)
    status = models.BooleanField()
    class Meta:
            unique_together = ['rule', 'connector']
    
    def __str__(self):
        return str(self.status)
    
class SPLByRule(models.Model):
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE)
    spl = models.TextField()
    class Meta:
            unique_together = ['rule', 'spl']
    
    def __str__(self):
        return str(self.spl)