from django.urls import path
from .views import ShiftListCreateView

urlpatterns = [
    path('', ShiftListCreateView.as_view(), name='shift-list-create'),
]
