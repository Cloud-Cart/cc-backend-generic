from celery import shared_task
from tenant_schemas_celery.task import TenantTask

from TenantEmails.choices import EmailTypeChoice
from TenantEmails.models import EmailTemplate
from TenantUsers.choices import InvitationStatus
from TenantUsers.models import TenantUser, TenantUserInvitation


@shared_task(base=TenantTask, bind=True, name='invite_tenant_user')
def send_user_invitation_email(tenant_user_id):
    tenant_user = TenantUser.objects.select_related('user').get(pk=tenant_user_id)
    if TenantUserInvitation.objects.filter(
            invitation_status__in=[InvitationStatus.SEND, InvitationStatus.RESEND],
            user=tenant_user
    ).exists():
        return

    user = tenant_user.user
    template = EmailTemplate.objects.get(type=EmailTypeChoice.INVITE_EMAIL)
    user.email_user(
        subject=template.subject,
        message=template.body,
    )
    TenantUserInvitation.objects.update_or_create(
        user=tenant_user,
        defaults={
            'invitation_status': InvitationStatus.SEND,
        }
    )
    tenant_user.save()
