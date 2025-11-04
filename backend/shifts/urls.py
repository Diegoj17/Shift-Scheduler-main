from django.urls import path
from . import views

urlpatterns = [
# ✅ API ENDPOINTS - Rutas limpias y consistentes
    # Turnos
    path('shifts/', views.ShiftListAPIView.as_view(), name='shift_list'),
    path('shifts/my/', views.MyShiftsAPIView.as_view(), name='my_shifts'),
    path('shifts/new/', views.ShiftCreateAPIView.as_view(), name='shift_api_create'),
    path('shifts/<int:pk>/edit/', views.ShiftUpdateAPIView.as_view(), name='shift_api_edit'),
    path('shifts/<int:pk>/delete/', views.ShiftDeleteAPIView.as_view(), name='shift_api_delete'),
    path('shifts/duplicate/', views.ShiftDuplicateAPIView.as_view(), name='shift_api_duplicate'),
    
    # Tipos de Turno
    path('shift-types/', views.ShiftTypeListAPIView.as_view(), name='shifttype_api_list'),
    path('shift-types/new/', views.ShiftTypeCreateAPIView.as_view(), name='shifttype_api_create'),
    path('shift-types/<int:pk>/edit/', views.ShiftTypeUpdateAPIView.as_view(), name='shifttype_api_edit'),
    path('shift-types/<int:pk>/delete/', views.ShiftTypeDeleteAPIView.as_view(), name='shifttype_api_delete'),
    
    
]
