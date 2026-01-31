import React, { useState, useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import './AiChatSidebar.css';

const MessageBubble = ({ msg }) => {
  const [copied, setCopied] = useState(false);
  
  const handleCopy = async () => {
    await window.electronAPI.copyToClipboard(msg.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`ai-message ${msg.role}`}>
      <div className="ai-message-bubble">
        <ReactMarkdown 
          remarkPlugins={[remarkGfm]}
          components={{
            code({node, inline, className, children, ...props}) {
              return !inline ? (
                <pre className="ai-code-block" {...props}>
                  <code>{children}</code>
                </pre>
              ) : (
                <code className="ai-code-inline" {...props}>
                  {children}
                </code>
              )
            }
          }}
        >
          {msg.content}
        </ReactMarkdown>
      </div>
      <div className="ai-message-footer">
        <button className="msg-copy-link" onClick={handleCopy}>
          {copied ? '已复制' : '复制'}
        </button>
      </div>
    </div>
  );
};

function AiChatSidebar({ isOpen, onClose, filePaths }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: '你好！我是 NetLens AI 助手。你可以问我关于当前 PCAP 文件的任何问题，或者让我帮你分析异常流量。' }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [aiReady, setAiConfigured] = useState(false);
  const [isWide, setIsWide] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    checkAiConfig();
  }, [isOpen]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const checkAiConfig = async () => {
    try {
      const settings = await window.electronAPI.getSettings();
      const profiles = settings.aiProfiles || [];
      const activeId = settings.activeProfileId;
      const activeProfile = profiles.find(p => p.id === activeId);
      
      setAiConfigured(!!(activeProfile && activeProfile.apiKey));
    } catch (err) {
      console.error('Failed to check AI config:', err);
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const handleSend = async (e) => {
    e.preventDefault();
    if (!input.trim() || isTyping) return;

    const userMessage = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    
    if (!aiReady) {
      setMessages(prev => [...prev, { role: 'assistant', content: '⚠️ 请先在设置中配置 AI API Key 才能开始对话。' }]);
      return;
    }

    setIsTyping(true);
    
    try {
      const response = await window.electronAPI.askAi(userMessage, filePaths);
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: response.content 
      }]);
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: '❌ 调用 AI 出错: ' + err.message }]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <div className={`ai-sidebar ${isOpen ? 'open' : 'closed'} ${isWide ? 'wide' : ''}`}>
        <div className="ai-sidebar-header sidebar-open">
        <div className="ai-title">
          <span className="ai-icon">🤖</span>
          <span>AI 分析师</span>
        </div>
          <div className="ai-header-content">
            <button className="ai-resize-btn" onClick={() => setIsWide(!isWide)} title={isWide ? "收起" : "展开"}>
                {isWide ? '»' : '«'} 
            </button>
            <button className="ai-close-btn" onClick={onClose}>×</button>
        </div>
      </div>

      <div className="ai-messages-container">
        {messages.map((msg, idx) => (
          <MessageBubble key={idx} msg={msg} />
        ))}
        {isTyping && (
          <div className="ai-message assistant">
            <div className="ai-message-bubble typing">
              <span className="dot"></span>
              <span className="dot"></span>
              <span className="dot"></span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form className="ai-input-area" onSubmit={handleSend}>
        <input 
          type="text" 
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={aiReady ? "问问 AI..." : "请先配置 AI..."}
          disabled={!aiReady || isTyping}
        />
        <button type="submit" disabled={!input.trim() || isTyping || !aiReady}>
          发送
        </button>
      </form>
    </div>
  );
}

export default AiChatSidebar;
