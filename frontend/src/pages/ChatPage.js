import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { getCookie } from '../utils/cookies';
import ChatLayout from '../pages/ChatLayout';
import Sidebar from '../components/Sidebar';
import Chat from '../pages/Chat';

function ChatPage() {
  const { user } = useAuth();
  const [sessions, setSessions] = useState([]);
  const [activeSession, setActiveSession] = useState(null);
  const [chatHistory, setChatHistory] = useState([]);
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [initialized, setInitialized] = useState(false);

  // Initialize chat sessions
  useEffect(() => {
    if (!user || initialized) return;

    const initializeChat = async () => {
      try {
        const res = await fetch("http://localhost:8000/geminiapi/sessions/", {
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
          },
        });
        const data = await res.json();
        
        if (data.length > 0) {
          setSessions(data);
          setActiveSession(data[0].id);
        }
        setInitialized(true);
      } catch (err) {
        console.error("Failed to load sessions:", err);
      }
    };

    initializeChat();
  }, [user, initialized]);

  // Load chat history when session changes
  useEffect(() => {
    if (!activeSession) return;

    const fetchHistory = async () => {
      try {
        const res = await fetch(`http://localhost:8000/geminiapi/sessions/${activeSession}/`, {
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
          },
        });
        const data = await res.json();
        setChatHistory(data.logs || []);
      } catch (err) {
        console.error("Failed to load chat history:", err);
      }
    };

    fetchHistory();
  }, [activeSession]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!message.trim()) return;

    setLoading(true);

    try {
      let sessionId = activeSession;
      
      // Create new session if none exists
      if (!sessionId) {
        const newSessionRes = await fetch("http://localhost:8000/geminiapi/sessions/new/", {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken"),
          },
          body: JSON.stringify({ title: message.substring(0, 30) }),
        });
        const newSession = await newSessionRes.json();
        setSessions([newSession, ...sessions]);
        setActiveSession(newSession.id);
        sessionId = newSession.id;
      }

      // Send message
      const res = await fetch(`http://localhost:8000/geminiapi/sessions/${sessionId}/chat/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCookie("csrftoken"),
        },
        credentials: "include",
        body: JSON.stringify({ message }),
      });

      const data = await res.json();

      if (res.ok) {
        setChatHistory(prev => [...prev, { message, response: data.response }]);
        setMessage('');
      }
    } catch (err) {
      console.error("Chat request failed:", err);
    }

    setLoading(false);
  };

  const createNewSession = () => {
    // Just reset the UI state for a new chat
    // We dont need to create a new session directly, only after user has typed a message
    setActiveSession(null);
    setChatHistory([]);
    setMessage('');
  };

  return (
    <ChatLayout
      sidebar={
        <Sidebar
          sessions={sessions}
          activeSession={activeSession}
          onSelectSession={setActiveSession}
          onCreateSession={createNewSession}
          onDeleteSession={(deletedSessionId) => {
            setSessions(sessions.filter(s => s.id !== deletedSessionId));
            if (activeSession === deletedSessionId) {
              setActiveSession(null);
              setChatHistory([]);
            }
          }}
        />
      }
      chatContent={
        <Chat
          history={chatHistory}
          loading={loading}
          onSubmit={handleSubmit}
          message={message}
          setMessage={setMessage}
        />
      }
    />
  );
}

export default ChatPage;