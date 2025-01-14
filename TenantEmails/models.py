from uuid import uuid4

from django.db.models import Model, UUIDField, CharField, TextField, DateTimeField, ForeignKey, CASCADE

from TenantEmails.choices import EmailTypeChoice


class EmailTemplate(Model):
    id = UUIDField(primary_key=True, default=uuid4, editable=False)
    type = CharField(max_length=100, choices=EmailTypeChoice.choices, unique=True)
    subject = CharField(max_length=255)
    body = TextField()
    updated_at = DateTimeField(auto_now=True)
    updated_by = ForeignKey('TenantUsers.TenantUser', on_delete=CASCADE, blank=False, null=True)

    class Meta:
        db_table = 'email_template'
        verbose_name = 'Email Template'
        verbose_name_plural = 'Email Templates'

    def __str__(self):
        return self.get_type_display()
