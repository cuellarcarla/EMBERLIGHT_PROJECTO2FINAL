import React from 'react';
import './ChatLayout.css';

function ChatLayout({ sidebar, chatContent }) {
  return (
    <div className="chat-layout">
      <div className="sidebar-container">
        {sidebar}
      </div>
      <div className="chat-content-container">
        {chatContent}
      </div>
    </div>
  );
}

export default ChatLayout;