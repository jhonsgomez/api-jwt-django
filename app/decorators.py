from functools import wraps
from rest_framework.response import Response
from rest_framework import status
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()


def jwt_token_required(view_func):
    @wraps(view_func)
    def wrapper(self, request, *args, **kwargs):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if not auth_header:
            return Response(
                {"error": "No se proporcionó token de autenticación"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            auth_parts = auth_header.split()
            if len(auth_parts) != 2 or auth_parts[0].lower() != "bearer":
                return Response(
                    {"error": "Formato de token inválido"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            token = auth_parts[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])
            request.user = user
        except jwt.ExpiredSignatureError:
            return Response(
                {"error": "Token expirado"}, status=status.HTTP_401_UNAUTHORIZED
            )
        except (jwt.InvalidTokenError, User.DoesNotExist):
            return Response(
                {"error": "Token inválido"}, status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            return Response(
                {"error": f"Error de autenticación: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return view_func(self, request, *args, **kwargs)

    return wrapper
