import React, { useState, useEffect } from 'react';
import { format, startOfWeek, addDays } from 'date-fns';
import { useAuth } from '../contexts/AuthContext';
import { getCookie } from "../utils/cookies";
import './JournalPage.css';
import WeekView from './WeekView';
import CalendarView from './CalendarView';

function JournalPage() {
  const { user } = useAuth();
  const [entries, setEntries] = useState([]);
  const [selectedDate, setSelectedDate] = useState(null);
  const [viewMode, setViewMode] = useState('week');
  const [editingDate, setEditingDate] = useState(null);
  const [currentMood, setCurrentMood] = useState('neutral');

  // Get the days of the week (Mon to Sun) where the current day(the day the user is viewing the website) belongs
  const getWeekDates = () => {
    const monday = startOfWeek(new Date(), { weekStartsOn: 1 }); // Return the start of a week for the given date, week starts on Monday
    return Array.from({ length: 7 }, (_, dayIndex) => addDays(monday, dayIndex));
  };

  // Format the dates for easy reading
  const toLocalDateString = date => format(date, 'yyyy-MM-dd');

  useEffect(() => {
    if (!user) return;

    // Retrieve the journal entries of the current user.
    // Note: Entries are retrieved only for the last 30 days and for the logged user.
    // This functionality is handled by the Django endpoint + sessions.
    const fetchEntries = async () => {
      try {
        const response = await fetch(`http://localhost:8000/journal/entries/`, {
          credentials: 'include',
          headers: {
            "Content-Type": "application/json",
            'X-CSRFToken': getCookie('csrftoken'),
          },
        });
        const data = await response.json();
        setEntries(data); // Store fetched entries to "entries" useState([]) array
      } catch (error) {
        console.error('Error fetching entries:', error);
      }
    };

    fetchEntries();
  }, [user]);

  const handleSave = async (date) => {
    const dateStr = toLocalDateString(date); // Get the date of the entry we're trying to store
    const textarea = document.querySelector(`textarea[data-date="${dateStr}"]`); // Get the text from textarea
    const text = textarea?.value || ''; // To prevent null in text area after saving
    const existingEntry = entries.find(e => e.date === dateStr); // Check if the date of that entry has already one entry stored in the DB

    // When pressing "Save" to store the entry to the DB, we check the fetched
    // entries to see if we stored the entry, of that specific date, previously to the DB.
    // Basically:
    // If the entry exists in the DB -> Edit the entry with PUT
    // If the entry doesn't exist in the DB -> Create a new entry with POST
    try {
      let response;
    
      if (existingEntry) {
        // Update existing entry (PATCH)
        response = await fetch(`http://localhost:8000/journal/entries/${existingEntry.id}/update/`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken'),
          },
          credentials: 'include',
          body: JSON.stringify({ mood: currentMood, text }),
        });
      } else {
        // Create new entry (POST)
        response = await fetch(`http://localhost:8000/journal/entries/create/`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken'),
          },
          credentials: 'include',
          body: JSON.stringify({ date: dateStr, mood: currentMood, text }),
        });
      }

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const savedEntry = await response.json();
      
      // Again, if the entry already existed in the DB, we check our
      // entries array and update it (if the entry existed) or append it if the entry is new
      setEntries(prev =>
        existingEntry
          ? prev.map(e => (e.id === savedEntry.id ? savedEntry : e))
          : [savedEntry, ...prev]
      );

      setEditingDate(null); // Finish editing the entry text
    } catch (error) {
      console.error('Error saving entry:', error);
    }
  };

  const handleDeleteEntry = async (entryId) => {
    try {
      const response = await fetch(`http://localhost:8000/journal/entries/${entryId}/delete/`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCookie('csrftoken'),
        },
        credentials: 'include',
      });

      if (response.ok) {
        setEntries(prev => prev.filter(e => e.id !== entryId));
        if (editingDate) setEditingDate(null);
      }
    } catch (error) {
      console.error('Error deleting entry:', error);
    }
  };

  const startEditing = (date, entry) => {
    setEditingDate(format(date, 'yyyy-MM-dd'));
    setCurrentMood(entry?.mood || 'neutral');
  };

  return (
    <div className="journal-page-wrapper">
    <div className="journal-container">
      <h1 style={{ color: "#2F5D46" }}>Tu Diario Mental</h1>

      <div className="view-toggle">
        <button 
          className={viewMode === 'week' ? 'active' : ''}
          onClick={() => setViewMode('week')}
        >
          Semanal
        </button>
        <button 
          className={viewMode === 'calendar' ? 'active' : ''}
          onClick={() => setViewMode('calendar')}
        >
          Calendario
        </button>
      </div>

      {viewMode === 'week' && (
        <WeekView
          entries={Array.isArray(entries) ? entries : []} 
          weekDates={getWeekDates()}
          editingDate={editingDate}
          currentMood={currentMood}
          setCurrentMood={setCurrentMood}
          handleSave={handleSave}
          startEditing={startEditing}
          handleDeleteEntry={handleDeleteEntry}
          setEditingDate={setEditingDate}
        />
      )}

      {viewMode === 'calendar' && (
        <CalendarView
          entries={entries}
          selectedDate={selectedDate}
          setSelectedDate={setSelectedDate}
        />
      )}
    </div>
    </div>
  );
}

export default JournalPage;
