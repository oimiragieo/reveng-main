/**
 * Progress Tracker Component
 * ==========================
 * 
 * Real-time progress tracking for analysis operations
 */

import React, { useState, useEffect } from 'react';
import { 
  CheckCircle, 
  Clock, 
  AlertCircle, 
  Loader, 
  Activity,
  Shield,
  Search,
  FileText,
  Zap
} from 'lucide-react';
import { useSocket } from '../../contexts/SocketContext';

const ProgressTracker = ({ analysisId, onComplete, onError }) => {
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [status, setStatus] = useState('created');
  const [steps, setSteps] = useState([]);
  
  const { getAnalysisStatus } = useSocket();

  // Analysis steps configuration
  const analysisSteps = [
    { id: 'foundation', name: 'Foundation Setup', icon: Activity, progress: 10 },
    { id: 'exposure', name: 'Corporate Exposure Analysis', icon: Shield, progress: 25 },
    { id: 'vulnerability', name: 'Vulnerability Discovery', icon: AlertCircle, progress: 40 },
    { id: 'intelligence', name: 'Threat Intelligence', icon: Search, progress: 55 },
    { id: 'reconstruction', name: 'Binary Reconstruction', icon: FileText, progress: 70 },
    { id: 'demonstration', name: 'Demonstration Generation', icon: Zap, progress: 80 },
    { id: 'ml-pipeline', name: 'ML Enhancement', icon: Activity, progress: 85 },
    { id: 'synthesis', name: 'Result Synthesis', icon: Activity, progress: 90 },
    { id: 'reporting', name: 'Report Generation', icon: FileText, progress: 95 }
  ];

  useEffect(() => {
    setSteps(analysisSteps.map(step => ({ ...step, completed: false, active: false })));
  }, []);

  // Listen for real-time updates
  useEffect(() => {
    const socketUpdate = getAnalysisStatus(analysisId);
    if (socketUpdate) {
      setProgress(socketUpdate.progress || 0);
      setStatus(socketUpdate.status || 'created');
      
      // Update current step based on progress
      const currentStepIndex = analysisSteps.findIndex(step => step.progress > socketUpdate.progress);
      const activeStepIndex = currentStepIndex > 0 ? currentStepIndex - 1 : 0;
      
      if (analysisSteps[activeStepIndex]) {
        setCurrentStep(analysisSteps[activeStepIndex].name);
        
        // Update steps completion status
        setSteps(prev => prev.map((step, index) => ({
          ...step,
          completed: index < activeStepIndex || socketUpdate.progress >= step.progress,
          active: index === activeStepIndex && socketUpdate.status === 'running'
        })));
      }
      
      // Handle completion or error
      if (socketUpdate.status === 'completed' && onComplete) {
        onComplete(socketUpdate);
      } else if (socketUpdate.status === 'failed' && onError) {
        onError(socketUpdate);
      }
    }
  }, [getAnalysisStatus, analysisId, onComplete, onError]);

  const getStepIcon = (step, index) => {
    const Icon = step.icon;
    
    if (step.completed) {
      return <CheckCircle className="h-5 w-5 text-green-500" />;
    } else if (step.active) {
      return <Loader className="h-5 w-5 text-blue-500 animate-spin" />;
    } else {
      return <Icon className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStepStatus = (step) => {
    if (step.completed) return 'completed';
    if (step.active) return 'active';
    return 'pending';
  };

  const getStatusColor = (stepStatus) => {
    switch (stepStatus) {
      case 'completed':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'active':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  return (
    <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-lg font-medium text-gray-900">Analysis Progress</h3>
          <span className="text-sm font-medium text-gray-600">{progress}%</span>
        </div>
        
        {/* Overall Progress Bar */}
        <div className="w-full bg-gray-200 rounded-full h-3">
          <div
            className="bg-blue-600 h-3 rounded-full transition-all duration-500 ease-out"
            style={{ width: `${progress}%` }}
          ></div>
        </div>
        
        {currentStep && status === 'running' && (
          <p className="mt-2 text-sm text-gray-600">
            Currently processing: <span className="font-medium">{currentStep}</span>
          </p>
        )}
      </div>

      {/* Step-by-step Progress */}
      <div className="space-y-3">
        <h4 className="text-sm font-medium text-gray-900 mb-3">Analysis Steps</h4>
        
        {steps.map((step, index) => {
          const stepStatus = getStepStatus(step);
          
          return (
            <div
              key={step.id}
              className={`flex items-center p-3 rounded-lg border ${getStatusColor(stepStatus)}`}
            >
              <div className="flex-shrink-0 mr-3">
                {getStepIcon(step, index)}
              </div>
              
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{step.name}</span>
                  <span className="text-xs">{step.progress}%</span>
                </div>
                
                {step.active && (
                  <div className="mt-1">
                    <div className="w-full bg-white bg-opacity-50 rounded-full h-1">
                      <div className="bg-blue-500 h-1 rounded-full animate-pulse w-3/4"></div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Status Messages */}
      {status === 'completed' && (
        <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-lg">
          <div className="flex items-center">
            <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
            <span className="text-sm font-medium text-green-800">Analysis completed successfully!</span>
          </div>
        </div>
      )}

      {status === 'failed' && (
        <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-red-500 mr-2" />
            <span className="text-sm font-medium text-red-800">Analysis failed. Please try again.</span>
          </div>
        </div>
      )}

      {/* Estimated Time */}
      {status === 'running' && (
        <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center">
            <Clock className="h-5 w-5 text-blue-500 mr-2" />
            <span className="text-sm text-blue-800">
              Estimated time remaining: {Math.max(1, Math.ceil((100 - progress) / 10))} minutes
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProgressTracker;