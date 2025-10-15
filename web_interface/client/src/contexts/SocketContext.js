/**
 * Socket Context
 * ==============
 * 
 * React context for managing WebSocket connections and real-time updates
 */

import React, { createContext, useContext, useEffect, useState } from 'react';
import io from 'socket.io-client';
import { useAuth } from './AuthContext';
import toast from 'react-hot-toast';

const SocketContext = createContext();

export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider');
  }
  return context;
};

export const SocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [analysisUpdates, setAnalysisUpdates] = useState(new Map());
  const { user, token, isAuthenticated } = useAuth();

  // Initialize socket connection
  useEffect(() => {
    if (isAuthenticated && token) {
      const newSocket = io(process.env.REACT_APP_SERVER_URL || 'http://localhost:5000', {
        auth: {
          token: token
        }
      });

      // Connection events
      newSocket.on('connect', () => {
        console.log('Socket connected:', newSocket.id);
        setConnected(true);
        
        // Authenticate socket
        newSocket.emit('authenticate', token);
      });

      newSocket.on('disconnect', () => {
        console.log('Socket disconnected');
        setConnected(false);
      });

      // Authentication events
      newSocket.on('auth-success', (data) => {
        console.log('Socket authenticated:', data);
        toast.success('Connected to real-time updates');
      });

      newSocket.on('auth-error', (data) => {
        console.error('Socket auth error:', data);
        toast.error('Failed to connect to real-time updates');
      });

      // Analysis events
      newSocket.on('analysis-created', (data) => {
        console.log('Analysis created:', data);
        toast.success(`Analysis created: ${data.fileName}`);
        updateAnalysisStatus(data.analysisId, data);
      });

      newSocket.on('analysis-started', (data) => {
        console.log('Analysis started:', data);
        toast.success('Analysis started');
        updateAnalysisStatus(data.analysisId, data);
      });

      newSocket.on('analysis-progress', (data) => {
        console.log('Analysis progress:', data);
        updateAnalysisStatus(data.analysisId, data);
      });

      newSocket.on('analysis-completed', (data) => {
        console.log('Analysis completed:', data);
        toast.success('Analysis completed successfully!');
        updateAnalysisStatus(data.analysisId, data);
      });

      newSocket.on('analysis-error', (data) => {
        console.log('Analysis error:', data);
        toast.error(`Analysis failed: ${data.error}`);
        updateAnalysisStatus(data.analysisId, data);
      });

      newSocket.on('analysis-deleted', (data) => {
        console.log('Analysis deleted:', data);
        toast.success('Analysis deleted');
        removeAnalysisStatus(data.analysisId);
      });

      newSocket.on('analysis-shared', (data) => {
        console.log('Analysis shared:', data);
        toast.success('An analysis has been shared with you');
      });

      // Collaboration events
      newSocket.on('user-joined', (data) => {
        console.log('User joined analysis:', data);
        toast.success(`${data.username} joined the analysis`);
      });

      newSocket.on('user-left', (data) => {
        console.log('User left analysis:', data);
        toast(`${data.username} left the analysis`);
      });

      newSocket.on('new-comment', (data) => {
        console.log('New comment:', data);
        toast.success('New comment added');
      });

      newSocket.on('collaboration-event', (data) => {
        console.log('Collaboration event:', data);
        // Handle collaboration events (annotations, highlights, etc.)
      });

      // Error handling
      newSocket.on('error', (data) => {
        console.error('Socket error:', data);
        toast.error(data.message || 'Socket error occurred');
      });

      setSocket(newSocket);

      return () => {
        newSocket.close();
        setSocket(null);
        setConnected(false);
      };
    }
  }, [isAuthenticated, token]);

  const updateAnalysisStatus = (analysisId, update) => {
    setAnalysisUpdates(prev => {
      const newMap = new Map(prev);
      const existing = newMap.get(analysisId) || {};
      newMap.set(analysisId, { ...existing, ...update });
      return newMap;
    });
  };

  const removeAnalysisStatus = (analysisId) => {
    setAnalysisUpdates(prev => {
      const newMap = new Map(prev);
      newMap.delete(analysisId);
      return newMap;
    });
  };

  const joinAnalysis = (analysisId) => {
    if (socket && connected) {
      socket.emit('join-analysis', analysisId);
    }
  };

  const leaveAnalysis = (analysisId) => {
    if (socket && connected) {
      socket.emit('leave-analysis', analysisId);
    }
  };

  const sendCollaborationEvent = (analysisId, eventType, payload) => {
    if (socket && connected) {
      socket.emit('collaboration-event', {
        analysisId,
        eventType,
        payload
      });
    }
  };

  const getAnalysisStatus = (analysisId) => {
    return analysisUpdates.get(analysisId);
  };

  const value = {
    socket,
    connected,
    analysisUpdates,
    joinAnalysis,
    leaveAnalysis,
    sendCollaborationEvent,
    getAnalysisStatus,
    updateAnalysisStatus,
    removeAnalysisStatus
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
};