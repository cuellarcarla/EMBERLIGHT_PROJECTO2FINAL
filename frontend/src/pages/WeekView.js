import React, { useRef, useEffect } from 'react';
import { format } from 'date-fns';

// Moods. First value: matches the database value. Must match the value from the django model.
// Second value: display for user visualization
const MOODS = [
  ['feliz', '😊'],
  ['neutral', '😐'],
  ['triste', '😢'],
  ['enojado', '😠'],
  ['ansioso', '😰'],
];

function WeekView({ entries, weekDates, editingDate, currentMood, setCurrentMood, handleSave, startEditing, handleDeleteEntry, setEditingDate }) {
  const textareaRef = useRef(null);

  // Check whenever we start editing the text area so the user can type or not.
  useEffect(() => {
    if (editingDate) {
      textareaRef.current?.focus();
    }
  }, [editingDate]);

  const toLocalDateString = date => format(date, 'yyyy-MM-dd');

  return (
    <div className="sticky-notes-container">
      { // We map the seven sticky notes (entries) of the current week
        weekDates.map((date) => {
        const dateStr = toLocalDateString(date);
        const entry = entries.find(e => e.date === dateStr);
        const isEditing = editingDate === dateStr;

        return (
          // We display the header with format: Day of the week (Ex: Martes) and Day of the month (Ex: 14)
          <div key={dateStr} className={`sticky-note ${entry ? entry.mood : 'empty'}`}>
            <div className="sticky-header" style={{ color: "#5F7F71" }}>
              {date.toLocaleDateString('es-ES', { weekday: 'long' })}
              <div className="sticky-date" style={{ color: "#5F7F71" }}>{date.getDate()}</div>
              <button 
                className="delete-entry-btn"
                onClick={(e) => {
                  e.stopPropagation();
                  if (entry) {
                    if (window.confirm('¿Estás seguro de que quieres eliminar esta entrada?')) {
                      handleDeleteEntry(entry.id);
                    }
                  } else {
                    alert('No hay ninguna entrada para eliminar en esta fecha.');
                  }
                }}
                title={entry ? "Eliminar entrada" : "No hay entrada para eliminar"}
              />
            </div>

            {isEditing ? (
              <div className="sticky-edit"> {/* If the user is editing... */}
                {/* We display the text area */}
                <textarea
                  ref={textareaRef}
                  defaultValue={entry?.text || ''}
                  placeholder="Escribe tus emociones..."
                  data-date={toLocalDateString(date)}
                />
                {/* We display the mood selector area */}
                <div className="mood-selector">
                  {MOODS.map(([value, emoji]) => (
                    <span
                      key={value}
                      className={currentMood === value ? 'selected' : ''}
                      onClick={() => setCurrentMood(value)}
                      title={value.charAt(0).toUpperCase() + value.slice(1)}
                    >
                      {emoji}
                    </span>
                  ))}
                </div>
                {/* We display the Save Button */}
                <div className="button-group">
                  <button onClick={() => handleSave(date)} className="save-button">
                    Guardar
                  </button>
                  <button 
                    onClick={() => setEditingDate(null)} 
                    className="cancel-button"
                  >
                    Cancelar
                  </button>
                </div>
              </div>
            ) : (
              <div className="sticky-content"> {/* If the user is NOT editing... */}
                <p>{entry?.text || 'Escribe tus emociones...'}</p>
                {/* We display an Edit or Add Entry button, based on if the entry exists in the DB */}
                <button onClick={() => startEditing(date, entry)} className="edit-button">
                  {entry ? 'Editar' : 'Crear Entrada'}
                </button>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default WeekView;
