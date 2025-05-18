from django.urls import path
from .views import (
    me, register, login_view, logout_view,
    get_users, get_user, update_user, delete_user, delete_user_data
)

urlpatterns = [
    path('me/', me, name='me'),
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('users/', get_users, name='get_users'),
    path('users/<int:user_id>/', get_user, name='get_user'),
    path('users/<int:user_id>/update/', update_user, name='update_user'),
    path('users/<int:user_id>/delete/', delete_user, name='delete_user'),
    path('users/delete-data/', delete_user_data, name='delete_user_data'),
]