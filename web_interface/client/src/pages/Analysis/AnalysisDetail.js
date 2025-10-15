/**
 * Analysis Detail Page
 * ====================
 * 
 * Detailed view of analysis results with real-time updates and interactive visualization
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Download, 
  Share2, 
  MessageSquare, 
  AlertTriangle, 
  Shield, 
  Eye, 
  FileText,
  Activity,
  Clock,
  CheckCircle,
  XCircle,
  Loader,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import { useSocket } from '../../contexts/SocketContext';
import { useAuth } from '../../contexts/AuthContext';
import axios from 'axios';
import toast from 'react-hot-toast';

const AnalysisDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { joinAnalysis, leaveAnalysis, getAnalysisStatus } = useSocket();
  
  const [analysis, setAnalysis] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedSections, setExpandedSections] = useState(new Set(['overview']));

  // Load analysis data
  useEffect(() => {
    const loadAnalysis = async () => {
      try {
        setLoading(true);
        
        // Get analysis status
        const statusResponse = await axios.get(`/api/analysis/${id}/status`);
        setAnalysis(statusResponse.data);
        
        // If completed, get results
        if (statusResponse.data.status === 'completed') {
          const resultsResponse = await axios.get(`/api/analysis/${id}/results`);
          setResults(resultsResponse.data);
        }
        
        // Join analysis room for real-time updates
        joinAnalysis(id);
        
      } catch (error) {
        console.error('Error loading analysis:', error);
        setError(error.response?.data?.message || 'Failed to load analysis');
        if (error.response?.status === 404) {
          navigate('/analysis');
        }
      } finally {
        setLoading(false);
      }
    };

    loadAnalysis();

    return () => {
      leaveAnalysis(id);
    };
  }, [id, joinAnalysis, leaveAnalysis, navigate]);

  // Listen for real-time updates
  useEffect(() => {
    const socketUpdate = getAnalysisStatus(id);
    if (socketUpdate) {
      setAnalysis(prev => ({ ...prev, ...socketUpdate }));
      
      // If analysis just completed, load results
      if (socketUpdate.status === 'completed' && !results) {
        loadResults();
      }
    }
  }, [getAnalysisStatus, id, results]);

  const loadResults = async () => {
    try {
      const response = await axios.get(`/api/analysis/${id}/results`);
      setResults(response.data);
    } catch (error) {
      console.error('Error loading results:', error);
      toast.error('Failed to load analysis results');
    }
  };

  const handleExport = async (format) => {
    try {
      const response = await axios.get(`/api/analysis/${id}/export/${format}`, {
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
      link.download = `analysis_${id}.${format}`;
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

  const toggleSection = (section) => {
    setExpandedSections(prev => {
      const newSet = new Set(prev);
      if (newSet.has(section)) {
        newSet.delete(section);
      } else {
        newSet.add(section);
      }
      return newSet;
    });
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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader className="h-8 w-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Loading analysis...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <XCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">Error Loading Analysis</h3>
        <p className="text-gray-500">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{analysis?.fileName}</h1>
            <div className="flex items-center mt-2 space-x-4">
              <div className="flex items-center">
                {getStatusIcon(analysis?.status)}
                <span className={`ml-2 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(analysis?.status)}`}>
                  {analysis?.status?.toUpperCase()}
                </span>
              </div>
              <span className="text-sm text-gray-500">
                Created: {new Date(analysis?.createdAt).toLocaleString()}
              </span>
              {analysis?.completedAt && (
                <span className="text-sm text-gray-500">
                  Completed: {new Date(analysis?.completedAt).toLocaleString()}
                </span>
              )}
            </div>
          </div>
          
          <div className="flex space-x-2">
            {analysis?.status === 'completed' && (
              <>
                <button
                  onClick={() => handleExport('json')}
                  className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                >
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </button>
                <button className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                  <Share2 className="h-4 w-4 mr-2" />
                  Share
                </button>
              </>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        {analysis?.status === 'running' && (
          <div className="mt-4">
            <div className="flex justify-between text-sm text-gray-600 mb-1">
              <span>Analysis Progress</span>
              <span>{analysis?.progress || 0}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${analysis?.progress || 0}%` }}
              ></div>
            </div>
          </div>
        )}

        {/* Error Display */}
        {analysis?.error && (
          <div className="mt-4 p-4 bg-red-50 rounded-md">
            <div className="flex">
              <XCircle className="h-5 w-5 text-red-400" />
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800">Analysis Failed</h3>
                <p className="mt-1 text-sm text-red-700">{analysis.error}</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Results Tabs */}
      {results && (
        <div className="bg-white shadow-sm rounded-lg border border-gray-200">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8 px-6">
              {[
                { id: 'overview', name: 'Overview', icon: Eye },
                { id: 'vulnerabilities', name: 'Vulnerabilities', icon: AlertTriangle },
                { id: 'corporate', name: 'Corporate Exposure', icon: Shield },
                { id: 'threat', name: 'Threat Intelligence', icon: Activity },
                { id: 'reconstruction', name: 'Reconstruction', icon: FileText }
              ].map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center ${
                      activeTab === tab.id
                        ? 'border-blue-500 text-blue-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                    }`}
                  >
                    <Icon className="h-4 w-4 mr-2" />
                    {tab.name}
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="p-6">
            {activeTab === 'overview' && (
              <AnalysisOverview results={results} />
            )}
            {activeTab === 'vulnerabilities' && (
              <VulnerabilityResults results={results?.vulnerabilities} />
            )}
            {activeTab === 'corporate' && (
              <CorporateExposureResults results={results?.corporate_exposure} />
            )}
            {activeTab === 'threat' && (
              <ThreatIntelligenceResults results={results?.threat_intelligence} />
            )}
            {activeTab === 'reconstruction' && (
              <ReconstructionResults results={results?.reconstruction} />
            )}
          </div>
        </div>
      )}

      {/* Waiting for Results */}
      {!results && analysis?.status !== 'failed' && (
        <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-12 text-center">
          {analysis?.status === 'running' ? (
            <>
              <Loader className="h-12 w-12 animate-spin text-blue-600 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Analysis in Progress</h3>
              <p className="text-gray-500">
                Your binary is being analyzed. This may take several minutes depending on file size and complexity.
              </p>
            </>
          ) : (
            <>
              <Clock className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Analysis Pending</h3>
              <p className="text-gray-500">
                Analysis has not started yet. Please wait for processing to begin.
              </p>
            </>
          )}
        </div>
      )}
    </div>
  );
};

// Analysis Overview Component
const AnalysisOverview = ({ results }) => {
  const summary = results?.executive_summary || {};
  
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-red-50 p-4 rounded-lg">
          <div className="flex items-center">
            <AlertTriangle className="h-8 w-8 text-red-600" />
            <div className="ml-3">
              <p className="text-sm font-medium text-red-800">Vulnerabilities</p>
              <p className="text-2xl font-bold text-red-900">
                {results?.vulnerabilities?.length || 0}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-yellow-50 p-4 rounded-lg">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-yellow-600" />
            <div className="ml-3">
              <p className="text-sm font-medium text-yellow-800">Data Exposures</p>
              <p className="text-2xl font-bold text-yellow-900">
                {results?.corporate_exposure?.credentials_found?.length || 0}
              </p>
            </div>
          </div>
        </div>
        
        <div className="bg-blue-50 p-4 rounded-lg">
          <div className="flex items-center">
            <Activity className="h-8 w-8 text-blue-600" />
            <div className="ml-3">
              <p className="text-sm font-medium text-blue-800">Threat Level</p>
              <p className="text-2xl font-bold text-blue-900">
                {results?.threat_intelligence?.threat_level || 'Unknown'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {summary.risk_assessment && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h3 className="text-lg font-medium text-gray-900 mb-2">Executive Summary</h3>
          <p className="text-gray-700">{summary.risk_assessment}</p>
        </div>
      )}
    </div>
  );
};

// Vulnerability Results Component
const VulnerabilityResults = ({ results }) => {
  if (!results || results.length === 0) {
    return (
      <div className="text-center py-8">
        <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900">No Vulnerabilities Found</h3>
        <p className="text-gray-500">The analysis did not identify any security vulnerabilities.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {results.map((vuln, index) => (
        <div key={index} className="border border-gray-200 rounded-lg p-4">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="text-lg font-medium text-gray-900">{vuln.title}</h4>
              <p className="text-sm text-gray-600 mt-1">{vuln.description}</p>
            </div>
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
              vuln.severity === 'high' ? 'bg-red-100 text-red-800' :
              vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
              'bg-green-100 text-green-800'
            }`}>
              {vuln.severity?.toUpperCase()}
            </span>
          </div>
          
          {vuln.location && (
            <div className="mt-2 text-sm text-gray-500">
              <strong>Location:</strong> {vuln.location}
            </div>
          )}
          
          {vuln.recommendation && (
            <div className="mt-2 text-sm text-gray-700">
              <strong>Recommendation:</strong> {vuln.recommendation}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

// Corporate Exposure Results Component
const CorporateExposureResults = ({ results }) => {
  if (!results) {
    return (
      <div className="text-center py-8">
        <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900">No Corporate Data Analysis</h3>
        <p className="text-gray-500">Corporate data exposure analysis was not performed.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {results.credentials_found && results.credentials_found.length > 0 && (
        <div>
          <h3 className="text-lg font-medium text-gray-900 mb-4">Exposed Credentials</h3>
          <div className="space-y-3">
            {results.credentials_found.map((cred, index) => (
              <div key={index} className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-center">
                  <AlertTriangle className="h-5 w-5 text-red-600" />
                  <span className="ml-2 font-medium text-red-800">{cred.type}</span>
                </div>
                <p className="mt-1 text-sm text-red-700">{cred.description}</p>
                {cred.location && (
                  <p className="mt-1 text-xs text-red-600">Found at: {cred.location}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {results.api_endpoints && results.api_endpoints.length > 0 && (
        <div>
          <h3 className="text-lg font-medium text-gray-900 mb-4">Discovered API Endpoints</h3>
          <div className="space-y-2">
            {results.api_endpoints.map((endpoint, index) => (
              <div key={index} className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                <code className="text-sm text-blue-800">{endpoint.url}</code>
                <p className="text-xs text-blue-600 mt-1">{endpoint.method} - {endpoint.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Threat Intelligence Results Component
const ThreatIntelligenceResults = ({ results }) => {
  if (!results) {
    return (
      <div className="text-center py-8">
        <Activity className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900">No Threat Intelligence</h3>
        <p className="text-gray-500">Threat intelligence analysis was not performed.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {results.malware_classification && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h3 className="text-lg font-medium text-yellow-800 mb-2">Malware Classification</h3>
          <p className="text-yellow-700">{results.malware_classification.family}</p>
          <p className="text-sm text-yellow-600 mt-1">
            Confidence: {results.malware_classification.confidence}%
          </p>
        </div>
      )}

      {results.iocs_extracted && results.iocs_extracted.length > 0 && (
        <div>
          <h3 className="text-lg font-medium text-gray-900 mb-4">Indicators of Compromise</h3>
          <div className="space-y-2">
            {results.iocs_extracted.map((ioc, index) => (
              <div key={index} className="bg-gray-50 border border-gray-200 rounded-lg p-3">
                <div className="flex justify-between items-center">
                  <code className="text-sm text-gray-800">{ioc.value}</code>
                  <span className="text-xs text-gray-500">{ioc.type}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// Reconstruction Results Component
const ReconstructionResults = ({ results }) => {
  if (!results) {
    return (
      <div className="text-center py-8">
        <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900">No Reconstruction Data</h3>
        <p className="text-gray-500">Binary reconstruction was not performed.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {results.source_code && (
        <div>
          <h3 className="text-lg font-medium text-gray-900 mb-4">Reconstructed Source Code</h3>
          <div className="bg-gray-900 rounded-lg p-4 overflow-x-auto">
            <pre className="text-green-400 text-sm">
              <code>{results.source_code}</code>
            </pre>
          </div>
        </div>
      )}

      {results.accuracy_metrics && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <h3 className="text-lg font-medium text-green-800 mb-2">Reconstruction Accuracy</h3>
          <p className="text-green-700">
            Functional Equivalence: {results.accuracy_metrics.functional_equivalence}%
          </p>
          <p className="text-green-700">
            Code Coverage: {results.accuracy_metrics.code_coverage}%
          </p>
        </div>
      )}
    </div>
  );
};

export default AnalysisDetail;