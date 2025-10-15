/**
 * Analysis Page
 * =============
 * 
 * File upload and analysis management interface with comprehensive analysis list
 */

import React, { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { Link } from 'react-router-dom';
import { 
  Upload, 
  File, 
  AlertCircle, 
  Search, 
  Filter, 
  Download, 
  Trash2, 
  Eye, 
  CheckCircle, 
  XCircle, 
  Clock, 
  Loader,
  RefreshCw
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useSocket } from '../../contexts/SocketContext';
import axios from 'axios';
import toast from 'react-hot-toast';

const Analysis = () => {
  const [uploading, setUploading] = useState(false);
  const [analysisConfig, setAnalysisConfig] = useState({
    noCorporate: false,
    noVuln: false,
    noThreat: false,
    noReconstruction: false,
    noDemo: false
  });
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [activeView, setActiveView] = useState('upload');

  const { user } = useAuth();
  const { joinAnalysis, analysisUpdates } = useSocket();

  // Load analyses on component mount
  useEffect(() => {
    loadAnalyses();
  }, []);

  const loadAnalyses = async () => {
    try {
      setLoading(true);
      const response = await axios.get('/api/analysis/user');
      setAnalyses(response.data.analyses || []);
    } catch (error) {
      console.error('Failed to load analyses:', error);
      toast.error('Failed to load analyses');
    } finally {
      setLoading(false);
    }
  };

  const onDrop = useCallback(async (acceptedFiles) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    
    // Validate file size (100MB limit)
    if (file.size > 100 * 1024 * 1024) {
      toast.error('File size must be less than 100MB');
      return;
    }

    setUploading(true);

    try {
      // Create form data
      const formData = new FormData();
      formData.append('binary', file);
      formData.append('config', JSON.stringify(analysisConfig));

      // Upload file
      const uploadResponse = await axios.post('/api/analysis/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });

      const { analysisId } = uploadResponse.data;

      // Join analysis room for real-time updates
      joinAnalysis(analysisId);

      // Start analysis
      await axios.post(`/api/analysis/${analysisId}/start`);

      toast.success('Analysis started successfully!');
      
      // Refresh analyses list
      loadAnalyses();
      
      // Switch to list view to see the new analysis
      setActiveView('list');

    } catch (error) {
      console.error('Upload error:', error);
      const message = error.response?.data?.message || 'Upload failed';
      toast.error(message);
    } finally {
      setUploading(false);
    }
  }, [analysisConfig, joinAnalysis]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    disabled: uploading
  });

  const handleConfigChange = (key) => {
    setAnalysisConfig(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  const handleDeleteAnalysis = async (analysisId) => {
    if (!window.confirm('Are you sure you want to delete this analysis?')) {
      return;
    }

    try {
      await axios.delete(`/api/analysis/${analysisId}`);
      toast.success('Analysis deleted successfully');
      loadAnalyses();
    } catch (error) {
      console.error('Delete error:', error);
      toast.error('Failed to delete analysis');
    }
  };

  const handleExportAnalysis = async (analysisId, format) => {
    try {
      const response = await axios.get(`/api/analysis/${analysisId}/export/${format}`, {
        responseType: format === 'pdf' ? 'blob' : 'text'
      });
      
      // Create download link
      const blob = new Blob([response.data], {
        type: format === 'json' ? 'application/json' : 
              format === 'xml' ? 'application/xml' :
              format === 'csv' ? 'text/csv' : 'application/pdf'
      });
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `analysis_${analysisId}.${format}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast.success(`Analysis exported as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Export error:', error);
      toast.error('Failed to export analysis');
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'running':
        return <Loader className="h-5 w-5 text-blue-500 animate-spin" />;
      default:
        return <Clock className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'text-green-600 bg-green-50';
      case 'failed':
        return 'text-red-600 bg-red-50';
      case 'running':
        return 'text-blue-600 bg-blue-50';
      default:
        return 'text-gray-600 bg-gray-50';
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Filter analyses based on search and status
  const filteredAnalyses = analyses.filter(analysis => {
    const matchesSearch = analysis.fileName.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || analysis.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Binary Analysis</h1>
          <p className="mt-1 text-sm text-gray-500">
            Upload binary files for AI-enhanced security analysis
          </p>
        </div>
        
        {/* View Toggle */}
        <div className="flex rounded-md shadow-sm">
          <button
            onClick={() => setActiveView('upload')}
            className={`px-4 py-2 text-sm font-medium rounded-l-md border ${
              activeView === 'upload'
                ? 'bg-blue-600 text-white border-blue-600'
                : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
            }`}
          >
            <Upload className="h-4 w-4 mr-2 inline" />
            Upload
          </button>
          <button
            onClick={() => setActiveView('list')}
            className={`px-4 py-2 text-sm font-medium rounded-r-md border-t border-r border-b ${
              activeView === 'list'
                ? 'bg-blue-600 text-white border-blue-600'
                : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
            }`}
          >
            <File className="h-4 w-4 mr-2 inline" />
            Analyses ({analyses.length})
          </button>
        </div>
      </div>

      {/* Upload View */}
      {activeView === 'upload' && (
        <>
          {/* Upload Area */}
          <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
            <div
              {...getRootProps()}
              className={`dropzone border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
                isDragActive
                  ? 'border-blue-400 bg-blue-50'
                  : 'border-gray-300 hover:border-gray-400'
              } ${uploading ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <input {...getInputProps()} />
              
              <div className="flex flex-col items-center">
                {uploading ? (
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mb-4"></div>
                ) : (
                  <Upload className="h-12 w-12 text-gray-400 mb-4" />
                )}
                
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  {uploading ? 'Uploading...' : 'Upload Binary File'}
                </h3>
                
                <p className="text-sm text-gray-500 mb-4">
                  {isDragActive
                    ? 'Drop the file here...'
                    : 'Drag and drop a binary file here, or click to select'}
                </p>
                
                <div className="flex items-center text-xs text-gray-400">
                  <File className="h-4 w-4 mr-1" />
                  <span>Supports: EXE, DLL, JAR, APK, JS, WASM and more (Max: 100MB)</span>
                </div>
              </div>
            </div>
          </div>

          {/* Analysis Configuration */}
          <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Analysis Configuration</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={!analysisConfig.noCorporate}
                  onChange={() => handleConfigChange('noCorporate')}
                  className="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">Corporate Data Exposure Analysis</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={!analysisConfig.noVuln}
                  onChange={() => handleConfigChange('noVuln')}
                  className="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">Vulnerability Discovery</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={!analysisConfig.noThreat}
                  onChange={() => handleConfigChange('noThreat')}
                  className="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">Threat Intelligence Correlation</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={!analysisConfig.noReconstruction}
                  onChange={() => handleConfigChange('noReconstruction')}
                  className="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">Binary Reconstruction</span>
              </label>

              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={!analysisConfig.noDemo}
                  onChange={() => handleConfigChange('noDemo')}
                  className="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50"
                />
                <span className="ml-2 text-sm text-gray-700">Demonstration Generation</span>
              </label>
            </div>

            <div className="mt-4 p-4 bg-yellow-50 rounded-md">
              <div className="flex">
                <AlertCircle className="h-5 w-5 text-yellow-400" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-yellow-800">
                    Analysis Configuration
                  </h3>
                  <div className="mt-2 text-sm text-yellow-700">
                    <p>
                      Enable or disable specific analysis modules. All modules are enabled by default
                      for comprehensive security analysis.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* List View */}
      {activeView === 'list' && (
        <>
          {/* Search and Filter */}
          <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-4">
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search analyses..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <Filter className="h-4 w-4 text-gray-400" />
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="border border-gray-300 rounded-md px-3 py-2 focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="all">All Status</option>
                  <option value="completed">Completed</option>
                  <option value="running">Running</option>
                  <option value="failed">Failed</option>
                  <option value="created">Created</option>
                </select>
                
                <button
                  onClick={loadAnalyses}
                  className="p-2 border border-gray-300 rounded-md hover:bg-gray-50"
                  title="Refresh"
                >
                  <RefreshCw className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>

          {/* Analyses List */}
          <div className="bg-white shadow-sm rounded-lg border border-gray-200">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader className="h-8 w-8 animate-spin text-blue-600" />
                <span className="ml-2 text-gray-600">Loading analyses...</span>
              </div>
            ) : filteredAnalyses.length > 0 ? (
              <div className="divide-y divide-gray-200">
                {filteredAnalyses.map((analysis) => {
                  const realtimeUpdate = analysisUpdates.get(analysis.id);
                  const currentStatus = realtimeUpdate?.status || analysis.status;
                  const currentProgress = realtimeUpdate?.progress || analysis.progress;
                  
                  return (
                    <div key={analysis.id} className="p-6 hover:bg-gray-50">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          {getStatusIcon(currentStatus)}
                          <div>
                            <Link
                              to={`/analysis/${analysis.id}`}
                              className="text-lg font-medium text-gray-900 hover:text-blue-600"
                            >
                              {analysis.fileName}
                            </Link>
                            <div className="flex items-center space-x-4 mt-1 text-sm text-gray-500">
                              <span>{formatFileSize(analysis.fileSize)}</span>
                              <span>•</span>
                              <span>Created: {new Date(analysis.createdAt).toLocaleString()}</span>
                              {analysis.completedAt && (
                                <>
                                  <span>•</span>
                                  <span>Completed: {new Date(analysis.completedAt).toLocaleString()}</span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-4">
                          {currentStatus === 'running' && (
                            <div className="flex items-center space-x-2">
                              <div className="w-32 bg-gray-200 rounded-full h-2">
                                <div
                                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                                  style={{ width: `${currentProgress || 0}%` }}
                                ></div>
                              </div>
                              <span className="text-sm text-gray-600">{currentProgress || 0}%</span>
                            </div>
                          )}
                          
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(currentStatus)}`}>
                            {currentStatus}
                          </span>
                          
                          <div className="flex items-center space-x-1">
                            <Link
                              to={`/analysis/${analysis.id}`}
                              className="p-2 text-gray-400 hover:text-gray-600"
                              title="View Details"
                            >
                              <Eye className="h-4 w-4" />
                            </Link>
                            
                            {currentStatus === 'completed' && (
                              <button
                                onClick={() => handleExportAnalysis(analysis.id, 'json')}
                                className="p-2 text-gray-400 hover:text-gray-600"
                                title="Export Results"
                              >
                                <Download className="h-4 w-4" />
                              </button>
                            )}
                            
                            <button
                              onClick={() => handleDeleteAnalysis(analysis.id)}
                              className="p-2 text-gray-400 hover:text-red-600"
                              title="Delete Analysis"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-12">
                <File className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900">
                  {searchTerm || statusFilter !== 'all' ? 'No matching analyses' : 'No analyses yet'}
                </h3>
                <p className="mt-1 text-sm text-gray-500">
                  {searchTerm || statusFilter !== 'all' 
                    ? 'Try adjusting your search or filter criteria.'
                    : 'Get started by uploading your first binary file for analysis.'
                  }
                </p>
                {!searchTerm && statusFilter === 'all' && (
                  <div className="mt-6">
                    <button
                      onClick={() => setActiveView('upload')}
                      className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
                    >
                      <Upload className="mr-2 h-4 w-4" />
                      Upload Binary
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default Analysis;