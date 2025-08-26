from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
    def email_validator(self, email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_("please enter a valid email address"))

    def create_user(self, email, full_name, phone_number, password=None, **kwargs):
        if not email:
            raise ValueError(_("an email address is required"))
        email = self.normalize_email(email)
        self.email_validator(email)
        if not full_name:
            raise ValueError(_("full name is required"))
        if not phone_number:
            raise ValueError(_("phone number is required"))
        user = self.model(email=email, full_name=full_name, phone_number=phone_number, **kwargs)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, phone_number, password=None, **kwargs):
        user = self.create_user(email, full_name, phone_number, password, **kwargs)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user
