from django.urls import path
from . import views

urlpatterns = [
    # Turnos
    path('', views.shift_calendar, name='shift_calendar'),
    path('shifts/', views.ShiftListView.as_view(), name='shift_list'),
    path('shifts/new/', views.ShiftCreateView.as_view(), name='shift_create'),
    path('shifts/<int:pk>/edit/', views.ShiftUpdateView.as_view(), name='shift_edit'),
    path('shifts/<int:pk>/delete/', views.ShiftDeleteView.as_view(), name='shift_delete'),
    path('shifts/duplicate/', views.shift_duplicate, name='shift_duplicate'),
    
    # Tipos de Turno - VISTAS HTML (para admin Django)
    path('shift-types/', views.ShiftTypeListView.as_view(), name='shifttype_list'),
    path('shift-types/new/', views.ShiftTypeCreateView.as_view(), name='shifttype_create'),
    path('shift-types/<int:pk>/edit/', views.ShiftTypeUpdateView.as_view(), name='shifttype_edit'),
    path('shift-types/<int:pk>/delete/', views.ShiftTypeDeleteView.as_view(), name='shifttype_delete'),
    
    # ✅ API ENDPOINTS - Para tu frontend React
    path('api/shift-types/', views.ShiftTypeListAPIView.as_view(), name='shifttype_api_list'),
    path('api/shift-types/new/', views.ShiftTypeCreateAPIView.as_view(), name='shifttype_api_create'),
    path('api/shift-types/<int:pk>/edit/', views.ShiftTypeUpdateAPIView.as_view(), name='shifttype_api_edit'),
    path('api/shift-types/<int:pk>/delete/', views.ShiftTypeDeleteAPIView.as_view(), name='shifttype_api_delete'),
]