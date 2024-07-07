import json
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .jwt_utils import get_tokens_for_user
from .models import UserRole  
from Authentication.models import CustomUser
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

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

        user, created = CustomUser.objects.get_or_create(username=email, defaults={'phone_number': phone_number})
        
        if created:
            user.set_password(password)
            user.role = role
            user.save()
            tokens = get_tokens_for_user(user)
            return Response(
                GenerateRequestResponse(
                    status=True,
                    status_code=201,
                    message="Account Created Successfully",
                    response={"tokens": tokens}
                ),
                headers={"Login-As": role}
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
            tokens = get_tokens_for_user(user)
            
            # Return success response
            return Response(
                GenerateRequestResponse(True, 200, "Login successful", {"tokens": tokens}),
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                GenerateRequestResponse(False, 500, f"An server error occurred => {str(e)}", None),
                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
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