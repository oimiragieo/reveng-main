/**
 * Results Visualization Component
 * ===============================
 * 
 * Interactive visualization of analysis results with charts and graphs
 */

import React, { useState } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import { 
  BarChart3, 
  PieChart, 
  TrendingUp, 
  AlertTriangle, 
  Shield, 
  Activity,
  Download,
  Maximize2
} from 'lucide-react';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement
);

const ResultsVisualization = ({ results, analysisId }) => {
  const [activeChart, setActiveChart] = useState('overview');
  const [fullscreen, setFullscreen] = useState(false);

  if (!results) {
    return (
      <div className="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div className="text-center py-8">
          <BarChart3 className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No Data Available</h3>
          <p className="mt-1 text-sm text-gray-500">
            Analysis results are not available for visualization.
          </p>
        </div>
      </div>
    );
  }

  // Prepare data for different chart types
  const vulnerabilityData = prepareVulnerabilityData(results);
  const riskDistributionData = prepareRiskDistributionData(results);
  const timelineData = prepareTimelineData(results);
  const threatLevelData = prepareThreatLevelData(results);

  const chartTypes = [
    { id: 'overview', name: 'Overview', icon: BarChart3 },
    { id: 'vulnerabilities', name: 'Vulnerabilities', icon: AlertTriangle },
    { id: 'risk', name: 'Risk Distribution', icon: PieChart },
    { id: 'timeline', name: 'Analysis Timeline', icon: TrendingUp },
    { id: 'threat', name: 'Threat Level', icon: Shield }
  ];

  const handleExportChart = () => {
    // Implementation for exporting chart as image
    toast.success('Chart export functionality will be implemented');
  };

  return (
    <div className={`bg-white shadow-sm rounded-lg border border-gray-200 ${fullscreen ? 'fixed inset-4 z-50' : ''}`}>
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-medium text-gray-900">Analysis Visualization</h3>
          
          <div className="flex items-center space-x-2">
            <button
              onClick={handleExportChart}
              className="p-2 text-gray-400 hover:text-gray-600"
              title="Export Chart"
            >
              <Download className="h-4 w-4" />
            </button>
            <button
              onClick={() => setFullscreen(!fullscreen)}
              className="p-2 text-gray-400 hover:text-gray-600"
              title="Toggle Fullscreen"
            >
              <Maximize2 className="h-4 w-4" />
            </button>
          </div>
        </div>
        
        {/* Chart Type Selector */}
        <div className="mt-4 flex space-x-1 bg-gray-100 rounded-lg p-1">
          {chartTypes.map((type) => {
            const Icon = type.icon;
            return (
              <button
                key={type.id}
                onClick={() => setActiveChart(type.id)}
                className={`flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeChart === type.id
                    ? 'bg-white text-blue-600 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                <Icon className="h-4 w-4 mr-2" />
                {type.name}
              </button>
            );
          })}
        </div>
      </div>

      {/* Chart Content */}
      <div className="p-6">
        {activeChart === 'overview' && (
          <OverviewChart data={vulnerabilityData} />
        )}
        
        {activeChart === 'vulnerabilities' && (
          <VulnerabilityChart data={vulnerabilityData} />
        )}
        
        {activeChart === 'risk' && (
          <RiskDistributionChart data={riskDistributionData} />
        )}
        
        {activeChart === 'timeline' && (
          <TimelineChart data={timelineData} />
        )}
        
        {activeChart === 'threat' && (
          <ThreatLevelChart data={threatLevelData} />
        )}
      </div>
    </div>
  );
};

// Overview Chart Component
const OverviewChart = ({ data }) => {
  const chartData = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    datasets: [
      {
        label: 'Vulnerabilities',
        data: [
          data.critical || 0,
          data.high || 0,
          data.medium || 0,
          data.low || 0,
          data.info || 0
        ],
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(245, 101, 101, 0.8)',
          'rgba(251, 191, 36, 0.8)',
          'rgba(34, 197, 94, 0.8)',
          'rgba(156, 163, 175, 0.8)'
        ],
        borderColor: [
          'rgba(239, 68, 68, 1)',
          'rgba(245, 101, 101, 1)',
          'rgba(251, 191, 36, 1)',
          'rgba(34, 197, 94, 1)',
          'rgba(156, 163, 175, 1)'
        ],
        borderWidth: 1
      }
    ]
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: true,
        text: 'Vulnerability Severity Distribution'
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1
        }
      }
    }
  };

  return <Bar data={chartData} options={options} />;
};

// Vulnerability Chart Component
const VulnerabilityChart = ({ data }) => {
  const chartData = {
    labels: Object.keys(data.byType || {}),
    datasets: [
      {
        label: 'Count',
        data: Object.values(data.byType || {}),
        backgroundColor: 'rgba(59, 130, 246, 0.8)',
        borderColor: 'rgba(59, 130, 246, 1)',
        borderWidth: 1
      }
    ]
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        display: false
      },
      title: {
        display: true,
        text: 'Vulnerabilities by Type'
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1
        }
      }
    }
  };

  return <Bar data={chartData} options={options} />;
};

// Risk Distribution Chart Component
const RiskDistributionChart = ({ data }) => {
  const chartData = {
    labels: ['High Risk', 'Medium Risk', 'Low Risk'],
    datasets: [
      {
        data: [data.high || 0, data.medium || 0, data.low || 0],
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(251, 191, 36, 0.8)',
          'rgba(34, 197, 94, 0.8)'
        ],
        borderColor: [
          'rgba(239, 68, 68, 1)',
          'rgba(251, 191, 36, 1)',
          'rgba(34, 197, 94, 1)'
        ],
        borderWidth: 2
      }
    ]
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'bottom'
      },
      title: {
        display: true,
        text: 'Overall Risk Distribution'
      }
    }
  };

  return <Doughnut data={chartData} options={options} />;
};

// Timeline Chart Component
const TimelineChart = ({ data }) => {
  const chartData = {
    labels: data.timeline?.map(point => point.step) || [],
    datasets: [
      {
        label: 'Progress',
        data: data.timeline?.map(point => point.progress) || [],
        borderColor: 'rgba(59, 130, 246, 1)',
        backgroundColor: 'rgba(59, 130, 246, 0.1)',
        tension: 0.4,
        fill: true
      }
    ]
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        display: false
      },
      title: {
        display: true,
        text: 'Analysis Progress Timeline'
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: {
          callback: function(value) {
            return value + '%';
          }
        }
      }
    }
  };

  return <Line data={chartData} options={options} />;
};

// Threat Level Chart Component
const ThreatLevelChart = ({ data }) => {
  const chartData = {
    labels: ['Malware Detection', 'Suspicious Behavior', 'IOC Matches', 'Risk Score'],
    datasets: [
      {
        label: 'Threat Indicators',
        data: [
          data.malware_score || 0,
          data.behavior_score || 0,
          data.ioc_matches || 0,
          data.overall_risk || 0
        ],
        backgroundColor: 'rgba(239, 68, 68, 0.8)',
        borderColor: 'rgba(239, 68, 68, 1)',
        borderWidth: 1
      }
    ]
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        display: false
      },
      title: {
        display: true,
        text: 'Threat Level Assessment'
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: {
          callback: function(value) {
            return value + '%';
          }
        }
      }
    }
  };

  return <Bar data={chartData} options={options} />;
};

// Data preparation functions
const prepareVulnerabilityData = (results) => {
  const vulnerabilities = results?.vulnerabilities || [];
  
  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  const typeCounts = {};

  vulnerabilities.forEach(vuln => {
    const severity = vuln.severity?.toLowerCase() || 'info';
    if (severityCounts.hasOwnProperty(severity)) {
      severityCounts[severity]++;
    }

    const type = vuln.type || 'Unknown';
    typeCounts[type] = (typeCounts[type] || 0) + 1;
  });

  return {
    ...severityCounts,
    byType: typeCounts
  };
};

const prepareRiskDistributionData = (results) => {
  // Calculate risk distribution based on various factors
  const corporateRisk = results?.corporate_exposure?.risk_level || 'low';
  const vulnRisk = results?.vulnerabilities?.length > 0 ? 'high' : 'low';
  const threatRisk = results?.threat_intelligence?.threat_level || 'low';

  const riskCounts = { high: 0, medium: 0, low: 0 };
  
  [corporateRisk, vulnRisk, threatRisk].forEach(risk => {
    if (riskCounts.hasOwnProperty(risk)) {
      riskCounts[risk]++;
    }
  });

  return riskCounts;
};

const prepareTimelineData = (results) => {
  // Mock timeline data - in real implementation, this would come from analysis logs
  return {
    timeline: [
      { step: 'Start', progress: 0 },
      { step: 'Foundation', progress: 10 },
      { step: 'Exposure', progress: 25 },
      { step: 'Vulnerability', progress: 40 },
      { step: 'Intelligence', progress: 55 },
      { step: 'Reconstruction', progress: 70 },
      { step: 'Demo', progress: 80 },
      { step: 'ML', progress: 85 },
      { step: 'Synthesis', progress: 90 },
      { step: 'Complete', progress: 100 }
    ]
  };
};

const prepareThreatLevelData = (results) => {
  const threatIntel = results?.threat_intelligence || {};
  
  return {
    malware_score: threatIntel.malware_classification?.confidence || 0,
    behavior_score: threatIntel.behavior_analysis?.risk_score || 0,
    ioc_matches: (threatIntel.iocs_extracted?.length || 0) * 10, // Scale to percentage
    overall_risk: threatIntel.threat_level === 'high' ? 80 : 
                  threatIntel.threat_level === 'medium' ? 50 : 20
  };
};

export default ResultsVisualization;