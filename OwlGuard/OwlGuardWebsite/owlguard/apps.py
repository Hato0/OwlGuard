from django.apps import AppConfig

class OwlguardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'owlguard'
    def ready(self):
        from . import tasks
        tasks.start()