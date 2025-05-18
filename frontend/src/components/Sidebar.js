import React, { useState } from 'react';
import './Sidebar.css';
import { getCookie } from '../utils/cookies';

function Sidebar({ sessions, activeSession, onSelectSession, onCreateSession, onDeleteSession }) {
  const [showDropdown, setShowDropdown] = useState(null);

  const handleDelete = async (sessionId, e) => {
    e.stopPropagation();
    const confirmDelete = window.confirm("Are you sure you want to delete this chat?");
    if (!confirmDelete) return;

    try {
      const res = await fetch(`http://localhost:8000/geminiapi/sessions/${sessionId}/delete`, {
        method: "DELETE",
        credentials: "include",
        headers: {
          "X-CSRFToken": getCookie("csrftoken"),
        },
      });
      
      if (res.ok) {
        // Refresh sessions
        onDeleteSession(sessionId);
      }
    } catch (err) {
      console.error("Failed to delete session:", err);
    }
  };

  const toggleDropdown = (sessionId, e) => {
    e.stopPropagation();
    setShowDropdown(showDropdown === sessionId ? null : sessionId);
  };

  return (
    <div className="sidebar">
      <div className="new-chat-button-container">
        <button className="new-chat-button" onClick={onCreateSession}>
          Nuevo Chat
        </button>
      </div>
      <div className="sessions-list">
        {sessions.map(session => (
          <div
            key={session.id}
            className={`session-item ${activeSession === session.id ? 'active' : ''}`}
            onClick={() => onSelectSession(session.id)}
          >
            <div className="session-title">{session.title}</div>
            <div 
              className="session-menu" 
              onClick={(e) => toggleDropdown(session.id, e)}
              onMouseEnter={(e) => e.currentTarget.classList.add('hovered')}
              onMouseLeave={(e) => e.currentTarget.classList.remove('hovered')}
            >
              <span>⋯</span>
              {showDropdown === session.id && (
                <div className="dropdown-menu" onClick={(e) => e.stopPropagation()}>
                  <div 
                    className="dropdown-item delete-item" 
                    onClick={(e) => handleDelete(session.id, e)}
                  >
                    Delete
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Sidebar;