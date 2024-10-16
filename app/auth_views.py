from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
import pytz
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import jwt
import datetime
from django.conf import settings
from .serializers import UserSerializer

User = get_user_model()


class RegisterView(APIView):
    def post(self, request):
        name = request.data.get("name")
        email = request.data.get("email")
        password = request.data.get("password")

        if not all([name, email, password]):
            return Response(
                {"error": "Se requieren los campos [name, email, password]"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "El email ya está registrado"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create_user(email=email, name=name, password=password)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = User.objects.filter(email=email).first()

        if user is None or not check_password(password, user.password):
            return Response(
                {"error": "Credenciales inválidas"}, status=status.HTTP_401_UNAUTHORIZED
            )

        payload = {
            "iat": datetime.datetime.now(pytz.timezone("America/Bogota")),
            "exp": datetime.datetime.now(pytz.timezone("America/Bogota"))
            + datetime.timedelta(minutes=60),
            "user_id": user.id,
            "user_name": user.name,
            "user_email": user.email,
            "user_roles": list(user.roles.values_list("name", flat=True)),
        }

        access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        refresh_payload = {
            "iat": datetime.datetime.now(pytz.timezone("America/Bogota")),
            "exp": datetime.datetime.now(pytz.timezone("America/Bogota"))
            + datetime.timedelta(days=7),
            "user_id": user.id,
            "user_name": user.name,
            "user_email": user.email,
            "user_roles": list(user.roles.values_list("name", flat=True)),
        }

        refresh_token = jwt.encode(
            refresh_payload, settings.SECRET_KEY, algorithm="HS256"
        )

        return Response({"access_token": access_token, "refresh_token": refresh_token})


class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return Response(
                {"error": "Se requiere el refresh token"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            payload = jwt.decode(
                refresh_token, settings.SECRET_KEY, algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return Response(
                {"error": "Refresh token expirado"}, status=status.HTTP_401_UNAUTHORIZED
            )
        except jwt.InvalidTokenError:
            return Response(
                {"error": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED
            )

        user = User.objects.filter(id=payload["user_id"]).first()

        if user is None:
            return Response(
                {"error": "Usuario no encontrado"}, status=status.HTTP_404_NOT_FOUND
            )

        new_payload = {
            "iat": datetime.datetime.now(pytz.timezone("America/Bogota")),
            "exp": datetime.datetime.now(pytz.timezone("America/Bogota"))
            + datetime.timedelta(days=7),
            "user_id": user.id,
            "user_name": user.name,
            "user_email": user.email,
            "user_roles": list(user.roles.values_list("name", flat=True)),
        }

        new_access_token = jwt.encode(
            new_payload, settings.SECRET_KEY, algorithm="HS256"
        )

        return Response({"access_token": new_access_token})
