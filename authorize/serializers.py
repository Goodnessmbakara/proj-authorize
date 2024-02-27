from rest_framework import serializers
from django.db import transaction


from django.contrib.auth import authenticate
# from django.contrib.sites.models import Site
from django.conf import settings

from rest_framework.authtoken.models import Token

from django.contrib.auth.password_validation import validate_password

from .models import User

class PasswordChangeSerializer(serializers.Serializer):
   """
   Serializer for password change endpoint.
   """
   old_password = serializers.CharField(required=True)
   new_password = serializers.CharField(required=True)
   confirm_new_password = serializers.CharField(required=True)

   def validate(self, data):
       """
       Check that the new password and confirmation match.
       """
       new_password = data.get("new_password")
       confirm_new_password = data.get("confirm_new_password")
       if new_password != confirm_new_password:
           raise serializers.ValidationError("New passwords must match")
       validate_password(new_password)
       return data

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email','id','password','password2', 'first_name', 'last_name']

    def validate(self, attrs):
        password=attrs.get('password','')
        password2=attrs.get('password2','')
        if password != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        validated_data.pop('password2', None)
        user = User.objects.create_user(**validated_data)
        return user

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)
    class Meta:
        model = User
        fields = ['token']

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(email=email, password=password)

            if user:
                data['user'] = user
            else:
                raise serializers.ValidationError("Invalid credentials. Please try again.")

        return data


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id',  'email')

