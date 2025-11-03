from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework import status

from .models import Shift
from .serializers import ShiftSerializer


class IsManagerOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.role in (user.Role.ADMIN, user.Role.GERENTE))


class ShiftListCreateView(generics.ListCreateAPIView):
    queryset = Shift.objects.all().select_related('employee')
    serializer_class = ShiftSerializer

    def get_permissions(self):
        if self.request.method == 'POST':
            return [permissions.IsAuthenticated(), IsManagerOrAdmin()]
        return [permissions.IsAuthenticated()]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Turno creado", "shift": serializer.data}, status=status.HTTP_201_CREATED, headers=headers)
