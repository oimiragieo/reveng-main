/**
 * Dashboard Page
 * ==============
 * 
 * Main dashboard with overview of analyses and system status
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { useSocket } from '../../contexts/SocketContext';
import {
  Upload,
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Users,
  Activity
} from 'lucide-react';
import axios from 'axios';

const Dashboard = () => {
  const { user } = useAuth();
  const { connected, analysisUpdates } = useSocket();
  const [stats, setStats] = useState({
    totalAnalyses: 0,
    completedAnalyses: 0,
    runningAnalyses: 0,
    failedAnalyses: 0
  });
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      // Load user analyses
      const response = await axios.get(`/api/analysis/user/${user.id}`);
      const analyses = response.data.analyses || [];
      
      setRecentAnalyses(analyses.slice(0, 5)); // Show 5 most recent
      
      // Calculate stats
      const stats = {
        totalAnalyses: analyses.length,
        completedAnalyses: analyses.filter(a => a.status === 'completed').length,
        runningAnalyses: analyses.filter(a => a.status === 'running').length,
        failedAnalyses: analyses.filter(a => a.status === 'failed').length
      };
      
      setStats(stats);
      
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'running':
        return <Clock className="h-5 w-5 text-blue-500" />;
      case 'failed':
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      default:
        return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'text-green-600 bg-green-100';
      case 'running':
        return 'text-blue-600 bg-blue-100';
      case 'failed':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500">
          Welcome back, {user?.username}! Here's what's happening with your analyses.
        </p>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Link
          to="/analysis"
          className="relative group bg-gradient-to-r from-blue-500 to-blue-600 p-6 rounded-lg shadow-sm hover:shadow-md transition-shadow"
        >
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Upload className="h-8 w-8 text-white" />
            </div>
            <div className="ml-4">
              <h3 className="text-lg font-medium text-white">Start New Analysis</h3>
              <p className="text-blue-100">Upload and analyze a binary file</p>
            </div>
          </div>
        </Link>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Activity className={`h-8 w-8 ${connected ? 'text-green-500' : 'text-red-500'}`} />
            </div>
            <div className="ml-4">
              <h3 className="text-lg font-medium text-gray-900">System Status</h3>
              <p className={`${connected ? 'text-green-600' : 'text-red-600'}`}>
                {connected ? 'Connected - Real-time updates active' : 'Disconnected - Limited functionality'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Search className="h-8 w-8 text-blue-500" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Analyses</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalAnalyses}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircle className="h-8 w-8 text-green-500" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Completed</p>
              <p className="text-2xl font-bold text-gray-900">{stats.completedAnalyses}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <Clock className="h-8 w-8 text-blue-500" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Running</p>
              <p className="text-2xl font-bold text-gray-900">{stats.runningAnalyses}</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <AlertTriangle className="h-8 w-8 text-red-500" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Failed</p>
              <p className="text-2xl font-bold text-gray-900">{stats.failedAnalyses}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Analyses */}
      <div className="bg-white shadow-sm rounded-lg border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Recent Analyses</h3>
        </div>
        <div className="divide-y divide-gray-200">
          {recentAnalyses.length > 0 ? (
            recentAnalyses.map((analysis) => {
              const realtimeUpdate = analysisUpdates.get(analysis.id);
              const currentStatus = realtimeUpdate?.status || analysis.status;
              const currentProgress = realtimeUpdate?.progress || analysis.progress;
              
              return (
                <div key={analysis.id} className="px-6 py-4 hover:bg-gray-50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {getStatusIcon(currentStatus)}
                      <div>
                        <Link
                          to={`/analysis/${analysis.id}`}
                          className="text-sm font-medium text-gray-900 hover:text-blue-600"
                        >
                          {analysis.fileName}
                        </Link>
                        <p className="text-sm text-gray-500">
                          {formatFileSize(analysis.fileSize)} • {new Date(analysis.createdAt).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {currentStatus === 'running' && (
                        <div className="w-24 bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${currentProgress || 0}%` }}
                          ></div>
                        </div>
                      )}
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(currentStatus)}`}>
                        {currentStatus}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="px-6 py-8 text-center">
              <Shield className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">No analyses yet</h3>
              <p className="mt-1 text-sm text-gray-500">
                Get started by uploading your first binary file for analysis.
              </p>
              <div className="mt-6">
                <Link
                  to="/analysis"
                  className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                >
                  <Upload className="mr-2 h-4 w-4" />
                  Upload Binary
                </Link>
              </div>
            </div>
          )}
        </div>
        {recentAnalyses.length > 0 && (
          <div className="px-6 py-3 bg-gray-50 border-t border-gray-200">
            <Link
              to="/analysis"
              className="text-sm font-medium text-blue-600 hover:text-blue-500"
            >
              View all analyses →
            </Link>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;