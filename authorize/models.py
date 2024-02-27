from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone

from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import Group, Permission

from . managers import UserManager

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(verbose_name=('email address'), unique = True)
    first_name=models.CharField(max_length=100, verbose_name=("First Name"), blank = True)
    last_name=models.CharField(max_length=100, verbose_name=("Last Name"), blank = True)
    passcode= models.IntegerField(null=True, blank=True)
    is_verified = models.BooleanField(default=False, null=True, blank=True)
    is_staff=models.BooleanField(default=False, null=True, blank=True)
    is_superuser = models.BooleanField(default=False, null=True, blank=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(default=timezone.now)
    # groups = models.ManyToManyField(Group)
    # user_permissions = models.ManyToManyField(Permission)


    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })



    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = []

    objects = UserManager()


    def __str__(self):
        return "{}".format(self.first_name)