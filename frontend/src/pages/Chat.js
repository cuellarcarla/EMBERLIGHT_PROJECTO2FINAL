import React, { useEffect, useState } from 'react';
import './Chat.css';

function Chat({ history, loading, onSubmit, message, setMessage }) {

  const formatMessage = (text) => {
    return text.split('**').map((part, index) => {
      return index % 2 === 0 ? part : <strong key={index}>{part}</strong>;
    });
  };

  return (
    <div className="chat-container">
      {history.length === 0 && !loading ? (
        <div className="empty-state">
          <h3>¿Cómo te sientes hoy?</h3>
          <p>Pregúntale a Emberlight AI lo que necesites</p>
        </div>
      ) : (
        <div className="chat-messages">
          {history.map((log, index) => (
            <React.Fragment key={index}>
              <div className="message user-message">
                <div className="message-content">{log.message}</div>
              </div>
              <div className="message ai-message">
                <div className="message-content">{formatMessage(log.response)}</div>
              </div>
            </React.Fragment>
          ))}
        </div>
      )}
      
      <form onSubmit={onSubmit} className="chat-input-area">
        <input
          type="text"
          className="chat-input"
          placeholder="Escribe tu mensaje a Emberlight..."
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          disabled={loading}
        />
        <button
          type="submit"
          className="send-button"
          disabled={loading || !message.trim()}
        >
          {loading ? "..." : "Enviar"}
        </button>
      </form>
    </div>
  );
}

export default Chat;