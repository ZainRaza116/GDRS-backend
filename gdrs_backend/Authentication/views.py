import json
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .jwt_utils import get_tokens_for_user
from .models import UserRole  
from Authentication.models import CustomUser, EmailVerification
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils.crypto import get_random_string

def GenerateRequestResponse(status, status_code, message , response):
    REQUEST_RESPONSE ={
        "status": status,
        "status_code": status_code,
        "message": message,
        "response": response

    }
    return REQUEST_RESPONSE

class SignupView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        phone_number = request.data.get('phone_number')
        role = UserRole.ADMIN.value 

        if not (email and password):
            return Response(
                GenerateRequestResponse(False, 400, "Email and Password are required")
            )

        user, created = CustomUser.objects.get_or_create(
            username=email, 
            defaults={
                'phone_number': phone_number,
                'is_active': False,
                'role': role
            }
        )
        
        if created:
            user.set_password(password)
            user.save()
            verification_code = get_random_string(length=6, allowed_chars='0123456789')
            EmailVerification.objects.create(user=user, code=verification_code)

            return Response(
                GenerateRequestResponse(
                    status=True,
                    status_code=201,
                    message="Account created. Please verify your email.",
                    response={"verification_code": verification_code} 
                )
            )
        else:
            return Response(
                GenerateRequestResponse(
                    status=False,
                    status_code=400,
                    message="User Already Exists",
                    response=None
                )
            )

class LoginView(APIView):
    def post(self, request):
        try:
            email = request.data.get("email")
            password = request.data.get("password")
            
            try:
                user = CustomUser.objects.get(username=email)
            except CustomUser.DoesNotExist:
                return Response(
                    GenerateRequestResponse(False, 400, "User not found", None),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not user.check_password(password):
                return Response(
                    GenerateRequestResponse(False, 400, "Invalid password", None),
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            if not user.is_active:

                verification_code = get_random_string(length=6, allowed_chars='0123456789')
                EmailVerification.objects.filter(user=user).delete()
                
                EmailVerification.objects.create(user=user, code=verification_code)
                
                return Response(
                    GenerateRequestResponse(False, 403, "Account not verified. A new verification code has been sent to your email.", 
                                            {"verification_code": verification_code}), 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            tokens = get_tokens_for_user(user)
        
            return Response(
                GenerateRequestResponse(True, 200, "Login successful", {"tokens": tokens}),
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                GenerateRequestResponse(False, 500, f"A server error occurred => {str(e)}", None),
                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VerifyEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')

        try:
            user = CustomUser.objects.get(username=email, is_active=False)
            verification = EmailVerification.objects.get(user=user, code=verification_code)
            
            if verification.is_expired:
                return Response(
                    GenerateRequestResponse(
                        status=False,
                        status_code=400,
                        message="Verification code has expired",
                        response=None
                    )
                )

            user.is_active = True
            user.save()
            verification.delete()

            tokens = get_tokens_for_user(user)
            return Response(
                GenerateRequestResponse(
                    status=True,
                    status_code=200,
                    message="Email verified successfully",
                    response={"tokens": tokens}
                ),
                headers={"Login-As": user.role}
            )
        except (CustomUser.DoesNotExist, EmailVerification.DoesNotExist):
            return Response(
                GenerateRequestResponse(
                    status=False,
                    status_code=400,
                    message="Invalid email or verification code",
                    response=None
                )
            )
    

class ChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.is_authenticated:
            return Response(
                GenerateRequestResponse(
                    status=False,
                    status_code=403,
                    message="Authentication Credentials not Found",
                    response=None
                ),
                status=403
            )

        data = json.loads(request.body)

        try:
            old_password = data.get("old_password")
            new_password = data.get("new_password")

            if not old_password or not new_password:
                return Response(
                    GenerateRequestResponse(
                        status=False,
                        status_code=400,
                        message="Old and New Password are required",
                        response=None
                    ),
                    status=400
                )

            if not user.check_password(old_password):
                return Response(
                    GenerateRequestResponse(
                        status=False,
                        status_code=400,
                        message="Old Password is incorrect",
                        response=None
                    ),
                    status=400
                )

            user.set_password(new_password)
            user.save()

            tokens = get_tokens_for_user(user)
            return Response(
                GenerateRequestResponse(
                    status=True,
                    status_code=200,
                    message="Password Has been Updated",
                    response={"tokens": tokens}
                ),
                status=200
            )
        except Exception as e:
            return Response(
                GenerateRequestResponse(
                    status=False,
                    status_code=500,
                    message=f"Server Error: {e}",
                    response=None
                ),
                status=500
            )
        
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')

        try:
            user = CustomUser.objects.get(username=email)

            verification_code = get_random_string(length=6, allowed_chars='0123456789')
            EmailVerification.objects.filter(user=user).delete()
            EmailVerification.objects.create(user=user, code=verification_code)
            return Response(
                GenerateRequestResponse(
                    status=True,
                    status_code=200,
                    message="Verification code sent to your email",
                    response={"verification_code": verification_code}  # Including code in the response for now
                )
            )

        except CustomUser.DoesNotExist:
            return Response(
                GenerateRequestResponse(
                    status=False,
                    status_code=400,
                    message="User with this email does not exist",
                    response=None
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

class ResetPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        new_password = request.data.get('new_password')

        try:
            user = CustomUser.objects.get(username=email)
            verification = EmailVerification.objects.get(user=user, code=verification_code)

            if verification.is_expired:
                return Response(
                    GenerateRequestResponse(
                        status=False,
                        status_code=400,
                        message="Verification code has expired",
                        response=None
                    )
                )
            user.is_active = True
            user.set_password(new_password)
            user.save()
            verification.delete()

            tokens = get_tokens_for_user(user)
            return Response(
                GenerateRequestResponse(
                    status=True,
                    status_code=200,
                    message="Password reset successfully",
                    response={"tokens": tokens}
                )
            )
        except (CustomUser.DoesNotExist, EmailVerification.DoesNotExist):
            return Response(
                GenerateRequestResponse(
                    status=False,
                    status_code=400,
                    message="Invalid email or verification code",
                    response=None
                )
            )
        except Exception as e:
            return Response(
                GenerateRequestResponse(
                    status=False,
                    status_code=500,
                    message=f"Server Error: {e}",
                    response=None
                ),
                status=500
            )