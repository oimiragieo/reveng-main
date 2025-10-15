/**
 * Analysis Service
 * ================
 * 
 * Core service for managing binary analysis operations including:
 * - Analysis job lifecycle management
 * - Integration with AI-Enhanced analyzer
 * - Real-time progress tracking
 * - Result storage and retrieval
 * - Collaborative features
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');

class AnalysisService {
  constructor() {
    this.activeAnalyses = new Map();
    this.analysisHistory = new Map();
    this.isHealthy_ = true;
    
    // Configuration
    this.config = {
      maxConcurrentAnalyses: 5,
      analysisTimeout: 3600000, // 1 hour
      pythonPath: process.env.PYTHON_PATH || 'python',
      analyzerPath: process.env.ANALYZER_PATH || '../tools/ai_enhanced_analyzer.py',
      resultsDir: path.join(__dirname, '../../reports'),
      tempDir: path.join(__dirname, '../../temp')
    };
    
    console.log('Analysis Service initialized');
  }

  /**
   * Create new analysis job
   */
  async createAnalysisJob(jobData) {
    const analysisId = uuidv4();
    
    const analysis = {
      id: analysisId,
      userId: jobData.userId,
      fileName: jobData.fileName,
      filePath: jobData.filePath,
      fileSize: jobData.fileSize,
      mimeType: jobData.mimeType,
      analysisConfig: jobData.analysisConfig || {},
      status: 'created',
      progress: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      startedAt: null,
      completedAt: null,
      error: null,
      results: null,
      sharedWith: [],
      comments: []
    };

    this.analysisHistory.set(analysisId, analysis);
    
    console.log(`Analysis job created: ${analysisId} for user ${jobData.userId}`);
    return analysis;
  }

  /**
   * Start analysis execution
   */
  async startAnalysis(analysisId, userId) {
    const analysis = this.analysisHistory.get(analysisId);
    
    if (!analysis) {
      throw new Error('Analysis not found');
    }
    
    if (analysis.userId !== userId) {
      throw new Error('Access denied');
    }
    
    if (analysis.status !== 'created') {
      throw new Error(`Analysis already ${analysis.status}`);
    }
    
    // Check concurrent analysis limit
    if (this.activeAnalyses.size >= this.config.maxConcurrentAnalyses) {
      throw new Error('Maximum concurrent analyses reached. Please try again later.');
    }
    
    // Update status
    analysis.status = 'running';
    analysis.startedAt = new Date().toISOString();
    analysis.updatedAt = new Date().toISOString();
    
    // Add to active analyses
    this.activeAnalyses.set(analysisId, analysis);
    
    // Start analysis process
    this._executeAnalysis(analysisId);
    
    return { status: 'started' };
  }

  /**
   * Execute analysis using AI-Enhanced analyzer
   */
  async _executeAnalysis(analysisId) {
    const analysis = this.activeAnalyses.get(analysisId);
    
    try {
      console.log(`Starting analysis execution: ${analysisId}`);
      
      // Prepare analysis command
      const analyzerPath = path.resolve(__dirname, '../../..', this.config.analyzerPath);
      const args = [analyzerPath, analysis.filePath];
      
      // Add configuration flags based on analysisConfig
      if (analysis.analysisConfig.noCorporate) {
        args.push('--no-corporate');
      }
      if (analysis.analysisConfig.noVuln) {
        args.push('--no-vuln');
      }
      if (analysis.analysisConfig.noThreat) {
        args.push('--no-threat');
      }
      if (analysis.analysisConfig.noReconstruction) {
        args.push('--no-reconstruction');
      }
      if (analysis.analysisConfig.noDemo) {
        args.push('--no-demo');
      }
      
      console.log(`Executing: ${this.config.pythonPath} ${args.join(' ')}`);
      
      // Spawn analysis process
      const analysisProcess = spawn(this.config.pythonPath, args, {
        cwd: path.resolve(__dirname, '../../..'),
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      let stdout = '';
      let stderr = '';
      
      // Handle stdout for progress tracking
      analysisProcess.stdout.on('data', (data) => {
        stdout += data.toString();
        this._parseProgressOutput(analysisId, data.toString());
      });
      
      // Handle stderr
      analysisProcess.stderr.on('data', (data) => {
        stderr += data.toString();
        console.error(`Analysis ${analysisId} stderr:`, data.toString());
      });
      
      // Handle process completion
      analysisProcess.on('close', async (code) => {
        try {
          if (code === 0) {
            await this._handleAnalysisSuccess(analysisId, stdout);
          } else {
            await this._handleAnalysisError(analysisId, stderr || 'Analysis process failed');
          }
        } catch (error) {
          console.error(`Error handling analysis completion: ${error.message}`);
          await this._handleAnalysisError(analysisId, error.message);
        }
      });
      
      // Handle process error
      analysisProcess.on('error', async (error) => {
        console.error(`Analysis process error: ${error.message}`);
        await this._handleAnalysisError(analysisId, error.message);
      });
      
      // Set timeout
      setTimeout(() => {
        if (this.activeAnalyses.has(analysisId)) {
          analysisProcess.kill('SIGTERM');
          this._handleAnalysisError(analysisId, 'Analysis timeout');
        }
      }, this.config.analysisTimeout);
      
    } catch (error) {
      console.error(`Error starting analysis: ${error.message}`);
      await this._handleAnalysisError(analysisId, error.message);
    }
  }

  /**
   * Parse progress output from analyzer
   */
  _parseProgressOutput(analysisId, output) {
    const analysis = this.activeAnalyses.get(analysisId);
    if (!analysis) return;
    
    // Parse progress indicators from output
    const progressPatterns = [
      { pattern: /\[FOUNDATION\]/, progress: 10 },
      { pattern: /\[EXPOSURE\]/, progress: 25 },
      { pattern: /\[VULNERABILITY\]/, progress: 40 },
      { pattern: /\[INTELLIGENCE\]/, progress: 55 },
      { pattern: /\[RECONSTRUCTION\]/, progress: 70 },
      { pattern: /\[DEMONSTRATION\]/, progress: 80 },
      { pattern: /\[ML-PIPELINE\]/, progress: 85 },
      { pattern: /\[SYNTHESIS\]/, progress: 90 },
      { pattern: /\[REPORTING\]/, progress: 95 }
    ];
    
    for (const { pattern, progress } of progressPatterns) {
      if (pattern.test(output)) {
        analysis.progress = progress;
        analysis.updatedAt = new Date().toISOString();
        break;
      }
    }
  }

  /**
   * Handle successful analysis completion
   */
  async _handleAnalysisSuccess(analysisId, stdout) {
    const analysis = this.activeAnalyses.get(analysisId);
    if (!analysis) return;
    
    try {
      // Look for analysis results folder
      const analysisFolder = path.join(
        path.dirname(analysis.filePath),
        `ai_enhanced_analysis_${path.parse(analysis.fileName).name}`
      );
      
      // Load analysis results
      const resultsFile = path.join(analysisFolder, 'universal_analysis_result.json');
      let results = null;
      
      try {
        const resultsData = await fs.readFile(resultsFile, 'utf8');
        results = JSON.parse(resultsData);
      } catch (error) {
        console.warn(`Could not load results file: ${error.message}`);
        // Create basic results from stdout
        results = {
          status: 'completed',
          output: stdout,
          message: 'Analysis completed but results file not found'
        };
      }
      
      // Update analysis
      analysis.status = 'completed';
      analysis.progress = 100;
      analysis.completedAt = new Date().toISOString();
      analysis.updatedAt = new Date().toISOString();
      analysis.results = results;
      
      // Move from active to history
      this.activeAnalyses.delete(analysisId);
      
      console.log(`Analysis completed successfully: ${analysisId}`);
      
    } catch (error) {
      console.error(`Error handling analysis success: ${error.message}`);
      await this._handleAnalysisError(analysisId, error.message);
    }
  }

  /**
   * Handle analysis error
   */
  async _handleAnalysisError(analysisId, errorMessage) {
    const analysis = this.activeAnalyses.get(analysisId) || this.analysisHistory.get(analysisId);
    if (!analysis) return;
    
    analysis.status = 'failed';
    analysis.error = errorMessage;
    analysis.completedAt = new Date().toISOString();
    analysis.updatedAt = new Date().toISOString();
    
    // Remove from active analyses
    this.activeAnalyses.delete(analysisId);
    
    console.error(`Analysis failed: ${analysisId} - ${errorMessage}`);
  }

  /**
   * Get analysis status
   */
  async getAnalysisStatus(analysisId, userId) {
    const analysis = this.analysisHistory.get(analysisId);
    
    if (!analysis) {
      throw new Error('Analysis not found');
    }
    
    // Check access permissions
    if (analysis.userId !== userId && !analysis.sharedWith.includes(userId)) {
      throw new Error('Access denied');
    }
    
    return {
      id: analysis.id,
      status: analysis.status,
      progress: analysis.progress,
      createdAt: analysis.createdAt,
      startedAt: analysis.startedAt,
      completedAt: analysis.completedAt,
      error: analysis.error,
      fileName: analysis.fileName,
      fileSize: analysis.fileSize
    };
  }

  /**
   * Get analysis results
   */
  async getAnalysisResults(analysisId, userId) {
    const analysis = this.analysisHistory.get(analysisId);
    
    if (!analysis) {
      throw new Error('Analysis not found');
    }
    
    // Check access permissions
    if (analysis.userId !== userId && !analysis.sharedWith.includes(userId)) {
      throw new Error('Access denied');
    }
    
    if (analysis.status !== 'completed') {
      throw new Error('Analysis not completed');
    }
    
    return analysis.results;
  }

  /**
   * Export analysis results
   */
  async exportResults(analysisId, format, userId) {
    const analysis = this.analysisHistory.get(analysisId);
    
    if (!analysis) {
      throw new Error('Analysis not found');
    }
    
    // Check access permissions
    if (analysis.userId !== userId && !analysis.sharedWith.includes(userId)) {
      throw new Error('Access denied');
    }
    
    if (analysis.status !== 'completed') {
      throw new Error('Analysis not completed');
    }
    
    const results = analysis.results;
    
    switch (format) {
      case 'json':
        return results;
      
      case 'xml':
        return this._convertToXML(results);
      
      case 'csv':
        return this._convertToCSV(results);
      
      case 'pdf':
        return await this._generatePDF(results);
      
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Delete analysis
   */
  async deleteAnalysis(analysisId, userId) {
    const analysis = this.analysisHistory.get(analysisId);
    
    if (!analysis) {
      throw new Error('Analysis not found');
    }
    
    if (analysis.userId !== userId) {
      throw new Error('Access denied');
    }
    
    // Stop if running
    if (this.activeAnalyses.has(analysisId)) {
      this.activeAnalyses.delete(analysisId);
    }
    
    // Delete files
    try {
      await fs.unlink(analysis.filePath);
    } catch (error) {
      console.warn(`Could not delete file: ${error.message}`);
    }
    
    // Remove from history
    this.analysisHistory.delete(analysisId);
    
    console.log(`Analysis deleted: ${analysisId}`);
  }

  /**
   * Get user analyses
   */
  async getUserAnalyses(userId) {
    const userAnalyses = [];
    
    for (const [id, analysis] of this.analysisHistory) {
      if (analysis.userId === userId || analysis.sharedWith.includes(userId)) {
        userAnalyses.push({
          id: analysis.id,
          fileName: analysis.fileName,
          fileSize: analysis.fileSize,
          status: analysis.status,
          progress: analysis.progress,
          createdAt: analysis.createdAt,
          completedAt: analysis.completedAt,
          isOwner: analysis.userId === userId
        });
      }
    }
    
    return userAnalyses.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  /**
   * Share analysis with users
   */
  async shareAnalysis(analysisId, ownerId, userIds, permissions) {
    const analysis = this.analysisHistory.get(analysisId);
    
    if (!analysis) {
      throw new Error('Analysis not found');
    }
    
    if (analysis.userId !== ownerId) {
      throw new Error('Access denied');
    }
    
    // Add users to shared list
    for (const userId of userIds) {
      if (!analysis.sharedWith.includes(userId)) {
        analysis.sharedWith.push(userId);
      }
    }
    
    analysis.updatedAt = new Date().toISOString();
    
    return {
      sharedWith: analysis.sharedWith,
      permissions: permissions
    };
  }

  /**
   * Add comment to analysis
   */
  async addComment(analysisId, userId, comment, section) {
    const analysis = this.analysisHistory.get(analysisId);
    
    if (!analysis) {
      throw new Error('Analysis not found');
    }
    
    // Check access permissions
    if (analysis.userId !== userId && !analysis.sharedWith.includes(userId)) {
      throw new Error('Access denied');
    }
    
    const commentObj = {
      id: uuidv4(),
      userId: userId,
      comment: comment,
      section: section,
      timestamp: new Date().toISOString()
    };
    
    analysis.comments.push(commentObj);
    analysis.updatedAt = new Date().toISOString();
    
    return commentObj;
  }

  /**
   * Convert results to XML format
   */
  _convertToXML(results) {
    // Simple XML conversion - could be enhanced with proper XML library
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<analysis>\n';
    
    function objectToXML(obj, indent = '  ') {
      let xml = '';
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'object' && value !== null) {
          xml += `${indent}<${key}>\n`;
          xml += objectToXML(value, indent + '  ');
          xml += `${indent}</${key}>\n`;
        } else {
          xml += `${indent}<${key}>${value}</${key}>\n`;
        }
      }
      return xml;
    }
    
    xml += objectToXML(results);
    xml += '</analysis>';
    
    return xml;
  }

  /**
   * Convert results to CSV format
   */
  _convertToCSV(results) {
    // Simple CSV conversion for flat data
    const rows = [];
    
    function flattenObject(obj, prefix = '') {
      const flattened = {};
      for (const [key, value] of Object.entries(obj)) {
        const newKey = prefix ? `${prefix}.${key}` : key;
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          Object.assign(flattened, flattenObject(value, newKey));
        } else {
          flattened[newKey] = Array.isArray(value) ? value.join(';') : value;
        }
      }
      return flattened;
    }
    
    const flattened = flattenObject(results);
    const headers = Object.keys(flattened);
    const values = Object.values(flattened);
    
    rows.push(headers.join(','));
    rows.push(values.map(v => `"${v}"`).join(','));
    
    return rows.join('\n');
  }

  /**
   * Generate PDF report
   */
  async _generatePDF(results) {
    // Placeholder for PDF generation
    // In a real implementation, you would use a library like puppeteer or jsPDF
    throw new Error('PDF export not yet implemented');
  }

  /**
   * Health check
   */
  isHealthy() {
    return this.isHealthy_;
  }
}

module.exports = AnalysisService;