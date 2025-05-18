from django.urls import path
from .views import (
    get_chat_sessions,
    create_chat_session,
    get_session_history,
    delete_chat_session,
    chat
)

urlpatterns = [
    # Sessions
    path('sessions/', get_chat_sessions, name='get-chat-sessions'),
    path('sessions/new/', create_chat_session, name='create-chat-session'),
    # Specific sessions
    path('sessions/<int:session_id>/', get_session_history, name='get-session-history'),
    path('sessions/<int:session_id>/chat/', chat, name='chat'),
    path('sessions/<int:session_id>/delete/', delete_chat_session, name='delete-chat'),
]