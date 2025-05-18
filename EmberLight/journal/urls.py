from django.urls import path
from .views import (
    getJournalEntries,
    createJournalEntry,
    getJournalEntry,
    updateJournalEntry,
    deleteJournalEntry
)

urlpatterns = [
    path('entries/', getJournalEntries, name='journal-entries'),
    path('entries/create/', createJournalEntry, name='journal-entry-create'),
    path('entries/<int:entry_id>/', getJournalEntry, name='journal-entry-detail'),
    path('entries/<int:entry_id>/update/', updateJournalEntry, name='journal-entry-update'),
    path('entries/<int:entry_id>/delete/', deleteJournalEntry, name='journal-entry-delete'),
]