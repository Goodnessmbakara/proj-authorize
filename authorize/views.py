from rest_framework.decorators import api_view

from rest_framework.response import Response

from rest_framework import status

from django.contrib.auth import get_user_model
from .serializers import *
from .import utils


from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from rest_framework import permissions
from rest_framework.generics import GenericAPIView,UpdateAPIView

from rest_framework.views import APIView

from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, TokenError, AccessToken

from rest_framework.pagination import PageNumberPagination

from django.contrib.sites.shortcuts import get_current_site

from django.urls import reverse
import jwt



from django.contrib.auth.hashers import check_password
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import update_session_auth_hash

User =  get_user_model()

class LoginAPIView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        response_data = {
            'access_token': str(access_token),
            'refresh_token': str(refresh),
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
        }

        return Response(response_data, status=status.HTTP_200_OK)

class VerifyEmailView(GenericAPIView ):
    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    View for user logout.

    Accepts a POST request with a refresh token and revokes the token, effectively logging the user out.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Handle POST request for user logout.

        Parameters:
        - `request` (HttpRequest): The incoming HTTP request containing the refresh token.

        Returns:
        - `Response`: JSON response indicating the success or failure of the logout operation.
        """
        try:
            # Extract the access token from the request
            access_token = request.headers.get('Authorization', '')[7:]

            refresh_token = RefreshToken.for_user(request.user)
            print(refresh_token)
            if not refresh_token:
                return Response({"detail": "Access token not provided."}, status=status.HTTP_400_BAD_REQUEST)

            # Blacklist the refresh token
            RefreshToken(refresh_token).blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_204_NO_CONTENT)

        except TokenError:
            return Response({"detail": "Invalid refresh token."}, status=status.HTTP_401_UNAUTHORIZED)

class ChangePasswordView(APIView):
    """
    View for changing user passwords.

    Requires authentication. Supports POST method.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for changing user passwords.

        Parameters:
        - request: The incoming HTTP request.

        Returns:
        - Response: JSON response indicating the result of the password change.
        """
        serializer = PasswordChangeSerializer(data=request.data)

        if serializer.is_valid():
            old_password = serializer.validated_data.get('old_password')
            new_password = serializer.validated_data.get('new_password')

            if not check_password(old_password, request.user.password):
                return Response({'detail': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)

            request.user.set_password(new_password)
            request.user.save()

            # Updating the session auth hash to avoid logouts after a password change
            update_session_auth_hash(request, request.user)

            return Response({'detail': 'Password updated successfully.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)

class DeleteAccountView(APIView):
    """
    View for deleting a user account.

    Requires authentication. Supports DELETE method.
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        """
        Handles DELETE requests for deleting a user account.

        Parameters:
        - request: The incoming HTTP request.

        Returns:
        - Response: JSON response indicating the result of the account deletion.
        """
        user = request.user
        user.delete()

        return Response({'detail': 'Account deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

class ResendVerificationEmailView(GenericAPIView):
    """
        ResendVerificationEmailView class handles resending verification emails.
    """
    serializer_class = UserRegisterSerializer

    def post(self, request):
       data = request.data
       email = data['email']

       try:
           user = User.objects.get(email=email)

           if user.is_verified:
               return Response({'msg':'User is already verified'})

           token = RefreshToken.for_user(user).access_token
           current_site = get_current_site(request).domain
           relative_link = reverse('email-verify')
           protocol = request.scheme
           absurl = protocol+'://'+current_site+relative_link+"?token="+str(token)
           email_body = 'Hi '+ user.first_name + ' this is the resent link to verify your email \n' + absurl

           data = {'email_body':email_body,'to_email':user.email,
                  'email_subject':'Verify your email'}
           utils.Util.send_email(data=data)

           return Response({'msg':'The verification email has been sent'}, status=status.HTTP_201_CREATED)
       except User.DoesNotExist:
           return Response({'msg':'No such user, register first'})

class RegisterView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
        user = serializer.data


        user_email = User.objects.get(email=user['email'])
        token = RefreshToken.for_user(user_email).access_token
        refresh_token = RefreshToken.for_user(user_email)
        # send email for user verification
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        protocol = request.scheme
        absurl = protocol+'://'+current_site+relative_link+"?token="+str(token)
        email_body = 'Hi '+ user['first_name'] + \
            ' Use the link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user['email'],
                'email_subject': 'Verify your email'}

        utils.Util.send_email(data=data)

        return Response({'user_data': user, 'access_token' : str(token), 'refresh_token' : str(refresh_token)}, status=status.HTTP_201_CREATED)


def generate_passcode():
    return get_random_string(length=6, allowed_chars='0123456789')

@api_view(['POST'])
def newPassword(request):
    data = request.data
    passcode = data.get('passcode')

    user = User.objects.filter(passcode=passcode).first()

    if user:
        new_password = data.get('new_password')
        user.set_password(new_password)
        user.save()

        # Updating the session auth hash to avoid logouts after a password change
        update_session_auth_hash(request, request.user)
        return Response({"message":"New password created"}, status=status.HTTP_201_CREATED)
    else:
        return Response({"message":"User doesnt exist"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def requestForgotPasswordPasscode(request):
    email = request.data.get('email', '')


    try:
        user = User.objects.get(email=email)
        passcode = generate_passcode()
        user.passcode= passcode
        user.save()

        # Send the passcode to the user's email
        email_subject = 'Forgot Password Passcode'
        email_body = f'Your passcode for resetting your password: {passcode}'
        data = {'email_subject' : email_subject,'email_body':email_body,'to_email':user.email}
        utils.Util.send_email(data)

        return Response({"message": "Passcode sent to your email."}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"detail": "User not found"}, status=status.HTTP_400_BAD_REQUEST)