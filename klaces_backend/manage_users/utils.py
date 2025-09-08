import logging
import random
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from .models import User, OneTimePasscode

logger = logging.getLogger(__name__)


def generate_otp(length=6):
    """Génère un code OTP numérique de la longueur spécifiée."""
    return ''.join(random.choices("0123456789", k=length))


def create_or_update_otp(user, length=6, expiration_minutes=5):
    """Crée ou met à jour un OTP pour un utilisateur."""
    otp_code = generate_otp(length)
    expires_at = timezone.now() + timedelta(minutes=expiration_minutes)

    existing_otp = OneTimePasscode.objects.filter(user=user).first()
    if existing_otp:
        existing_otp.code = otp_code
        existing_otp.expires_at = expires_at
        existing_otp.save()
    else:
        OneTimePasscode.objects.create(user=user, code=otp_code, expires_at=expires_at)

    return otp_code


def send_otp_email(user):
    """
    Envoie un code OTP à l'utilisateur par email (synchrone).
    L'argument doit être un objet User.
    """
    try:
        otp_code = create_or_update_otp(user)

        subject = "Code OTP pour la vérification de votre email"
        email_body = render_to_string("otp_email.html", {
            "otp": otp_code,
            "user": user,
            "current_site": "Klaces Web App"
        })

        email = EmailMessage(subject, email_body, settings.EMAIL_HOST_USER, [user.email])
        email.content_subtype = "html"
        email.send(fail_silently=False)

        logger.info(f"OTP envoyé à {user.email}")
        return True
    except Exception as e:
        logger.error(f"Erreur OTP : {str(e)}")
        return False

def send_normal_email(data):
    email=EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()




