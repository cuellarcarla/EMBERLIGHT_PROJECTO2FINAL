from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import login, logout, get_user_model
from django.shortcuts import get_object_or_404
from .serializers import UserSerializer, RegisterSerializer, LoginSerializer
from journal.models import JournalEntry
from chat.models import ChatSession

User = get_user_model() # We get the user from the setting.py

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "User created"}, status=status.HTTP_201_CREATED)
    errors = {}
    for field, error_list in serializer.errors.items():
        errors[field] = error_list[0] if error_list else "Invalid value"
    return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        login(request, serializer.validated_data['user'])
        return Response(UserSerializer(serializer.validated_data['user']).data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    logout(request)
    return Response({"message": "Logged out"})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me(request):
    return Response(UserSerializer(request.user).data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_users(request):
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    serializer = UserSerializer(user)
    return Response(serializer.data)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_user(request, user_id):

    user = get_object_or_404(User, id=user_id)

    if request.user != user:
        return Response(
            {"error": "Cannot update other users"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = UserSerializer(user, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)

    errors = {}
    for field, error_list in serializer.errors.items():
        errors[field] = error_list[0] if error_list else "Invalid value"
    return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user(request, user_id):

    user = get_object_or_404(User, id=user_id)

    if request.user != user:
        return Response(
            {"error": "Cannot delete other users"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    user.delete()
    logout(request)
    return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_user_data(request):
    user = request.user
    
    JournalEntry.objects.filter(user=user).delete()
    
    ChatSession.objects.filter(user=user).delete()
    # Note: ChatLogs will be deleted automatically due to CASCADE
    
    return Response(
        {"message": "All your personal data has been deleted"},
        status=status.HTTP_204_NO_CONTENT
    )