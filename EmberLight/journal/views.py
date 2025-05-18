from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import JournalEntry
from .serializers import JournalEntrySerializer
from django.utils import timezone
from datetime import timedelta

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getJournalEntries(request):
    # Get entries from the last 30 days by default
    date_from = timezone.now().date() - timedelta(days=30)
    entries = JournalEntry.objects.filter(
        user=request.user,
        date__gte=date_from
    ).order_by('-date')
    
    serializer = JournalEntrySerializer(entries, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def createJournalEntry(request):
    # Check if entry already exists for this date
    date = request.data.get('date')
    existing_entry = JournalEntry.objects.filter(
        user=request.user,
        date=date
    ).first()
    
    if existing_entry:
        return Response(
            {"error": "Entry already exists for this date. Use update instead."},
            status=status.HTTP_400_BAD_REQUEST
        )
        
    serializer = JournalEntrySerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(user=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def getJournalEntry(request, entry_id):
    try:
        entry = JournalEntry.objects.get(id=entry_id, user=request.user)
    except JournalEntry.DoesNotExist:
        return Response({"error": "Journal entry not found."}, status=status.HTTP_404_NOT_FOUND)
    
    serializer = JournalEntrySerializer(entry)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def updateJournalEntry(request, entry_id):
    try:
        entry = JournalEntry.objects.get(id=entry_id, user=request.user)
    except JournalEntry.DoesNotExist:
        return Response({"error": "Journal entry not found."}, status=status.HTTP_404_NOT_FOUND)
    
    serializer = JournalEntrySerializer(entry, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def deleteJournalEntry(request, entry_id):
    try:
        entry = JournalEntry.objects.get(id=entry_id, user=request.user)
    except JournalEntry.DoesNotExist:
        return Response({"error": "Journal entry not found."}, status=status.HTTP_404_NOT_FOUND)
    
    entry.delete()
    return Response({"message": "Journal entry deleted successfully."}, status=status.HTTP_204_NO_CONTENT)