from celery import shared_task
from tenant_schemas_celery.task import TenantTask

from TenantEmails.choices import EmailTypeChoice
from TenantEmails.models import EmailTemplate
from TenantUsers.choices import InvitationStatus
from TenantUsers.models import TenantUser, TenantUserInvitation


@shared_task(base=TenantTask, bind=True, name='invite_tenant_user')
def send_user_invitation_email(invitation_id):
    invitation = TenantUserInvitation.objects.get(pk=invitation_id)
    tenant_user = invitation.user
    if TenantUserInvitation.objects.filter(
            invitation_status__in=[InvitationStatus.SEND, InvitationStatus.RESEND],
            user=tenant_user
    ).exists():
        return
    user = tenant_user.user
    tenant_user_invitation, _ = TenantUserInvitation.objects.update_or_create(
        user=tenant_user,
        defaults={
            'invitation_status': InvitationStatus.SEND,
        }
    )
    secret = tenant_user_invitation.generate_hash()

    template = EmailTemplate.objects.get(type=EmailTypeChoice.INVITE_EMAIL)
    user.email_user(
        subject=template.subject,
        message=template.body,
    )

    tenant_user.save()
