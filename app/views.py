from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User, Role, Permission
from .decorators import jwt_token_required
from .serializers import UserSerializer, RoleSerializer, PermissionSerializer


class UserView(APIView):
    @jwt_token_required
    def get(self, request, user_id=None):
        if user_id:
            user = User.objects.filter(id=user_id).first()
            if not user:
                return Response(
                    {"error": "Usuario no encontrado"}, status=status.HTTP_404_NOT_FOUND
                )
            serializer = UserSerializer(user)
        else:
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    @jwt_token_required
    def post(self, request):
        name = request.data.get("name")
        email = request.data.get("email")
        password = request.data.get("password")

        if not all([name, email, password]):
            return Response(
                {"error": "Se requieren los campos: [name, email, password]"},
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

    @jwt_token_required
    def put(self, request, user_id):
        user = User.objects.filter(id=user_id).first()
        if not user:
            return Response(
                {"error": "Usuario no encontrado"}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if "password" in request.data:
                user.set_password(request.data["password"])
            if "roles" in request.data:
                role_names = request.data["roles"]
                roles = Role.objects.filter(name__in=role_names)
                user.roles.set(roles)
            if "permissions" in request.data:
                permission_names = request.data["permissions"]
                permissions = Permission.objects.filter(name__in=permission_names)
                user.permissions.set(permissions)
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @jwt_token_required
    def delete(self, request, user_id):
        user = User.objects.filter(id=user_id).first()
        if not user:
            return Response(
                {"error": "Usuario no encontrado"}, status=status.HTTP_404_NOT_FOUND
            )

        user.delete()
        return Response(
            {"message": "Usuario eliminado correctamente"},
            status=status.HTTP_204_NO_CONTENT,
        )


class RoleView(APIView):
    @jwt_token_required
    def get(self, request, role_id=None):
        if role_id:
            role = Role.objects.filter(id=role_id).first()
            if not role:
                return Response(
                    {"error": "Rol no encontrado"}, status=status.HTTP_404_NOT_FOUND
                )
            serializer = RoleSerializer(role)
        else:
            roles = Role.objects.all()
            serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data)

    @jwt_token_required
    def post(self, request):
        if " " in request.data["name"]:
            return Response(
                {"error": "El nombre no debe contener espacios"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if "name" in request.data:
            request.data["name"] = request.data["name"].lower()

        serializer = RoleSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @jwt_token_required
    def put(self, request, role_id):
        role = Role.objects.filter(id=role_id).first()
        if not role:
            return Response(
                {"error": "Rol no encontrado"}, status=status.HTTP_404_NOT_FOUND
            )

        if " " in request.data["name"]:
            return Response(
                {"error": "El nombre no debe contener espacios"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if "name" in request.data:
            request.data["name"] = request.data["name"].lower()

        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @jwt_token_required
    def delete(self, request, role_id):
        role = Role.objects.filter(id=role_id).first()
        if not role:
            return Response(
                {"error": "Rol no encontrado"}, status=status.HTTP_404_NOT_FOUND
            )

        role.delete()
        return Response(
            {"message": "Rol eliminado correctamente"},
            status=status.HTTP_204_NO_CONTENT,
        )


class PermissionView(APIView):
    @jwt_token_required
    def get(self, request, permission_id=None):
        if permission_id:
            permission = Permission.objects.filter(id=permission_id).first()
            if not permission:
                return Response(
                    {"error": "Permiso no encontrado"}, status=status.HTTP_404_NOT_FOUND
                )
            serializer = PermissionSerializer(permission)
        else:
            permissions = Permission.objects.all()
            serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data)

    @jwt_token_required
    def post(self, request):
        if " " in request.data["name"]:
            return Response(
                {"error": "El nombre no debe contener espacios"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if "name" in request.data:
            request.data["name"] = request.data["name"].lower()

        serializer = PermissionSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @jwt_token_required
    def put(self, request, permission_id):
        permission = Permission.objects.filter(id=permission_id).first()
        if not permission:
            return Response(
                {"error": "Permiso no encontrado"}, status=status.HTTP_404_NOT_FOUND
            )

        if " " in request.data["name"]:
            return Response(
                {"error": "El nombre no debe contener espacios"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if "name" in request.data:
            request.data["name"] = request.data["name"].lower()

        serializer = PermissionSerializer(permission, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @jwt_token_required
    def delete(self, request, permission_id):
        permission = Permission.objects.filter(id=permission_id).first()
        if not permission:
            return Response(
                {"error": "Permiso no encontrado"}, status=status.HTTP_404_NOT_FOUND
            )

        permission.delete()
        return Response(
            {"message": "Permiso eliminado correctamente"},
            status=status.HTTP_204_NO_CONTENT,
        )
