#!/usr/bin/env node
/**
 * Analysis Worker Service
 * ======================
 * 
 * Dedicated worker process for handling analysis tasks.
 * Processes jobs from Redis queue and communicates with AI service.
 */

const express = require('express');
const Redis = require('ioredis');
const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');

// Configuration
const config = {
    port: process.env.PORT || 3001,
    redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
    aiServiceUrl: process.env.AI_SERVICE_URL || 'http://ai-service:8000',
    pythonPath: process.env.PYTHON_PATH || 'python3',
    analyzerPath: process.env.ANALYZER_PATH || '/app/reveng_analyzer.py',
    workerConcurrency: parseInt(process.env.WORKER_CONCURRENCY) || 2,
    maxJobTime: parseInt(process.env.MAX_JOB_TIME) || 3600000, // 1 hour
};

// Initialize Redis client
const redis = new Redis(config.redisUrl, {
    retryDelayOnFailover: 100,
    enableReadyCheck: false,
    maxRetriesPerRequest: null,
});

// Initialize Express app for health checks
const app = express();
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'analysis-worker',
        version: '1.0.0',
        concurrency: config.workerConcurrency,
        activeJobs: activeJobs.size
    });
});

// Track active jobs
const activeJobs = new Map();

/**
 * Process analysis job
 */
async function processAnalysisJob(jobData) {
    const { jobId, filePath, options = {} } = jobData;
    
    console.log(`[${jobId}] Starting analysis for: ${filePath}`);
    
    try {
        // Update job status
        await redis.hset(`job:${jobId}`, {
            status: 'processing',
            startTime: Date.now(),
            worker: process.env.HOSTNAME || 'unknown'
        });
        
        // Run basic REVENG analysis
        const revengResult = await runRevengAnalysis(filePath, options);
        
        // Run enhanced AI analysis if enabled
        let enhancedResult = null;
        if (options.enhancedAnalysis) {
            enhancedResult = await runEnhancedAnalysis(filePath, revengResult, options);
        }
        
        // Combine results
        const finalResult = {
            reveng: revengResult,
            enhanced: enhancedResult,
            metadata: {
                jobId,
                filePath,
                completedAt: new Date().toISOString(),
                worker: process.env.HOSTNAME || 'unknown'
            }
        };
        
        // Store result
        await redis.hset(`job:${jobId}`, {
            status: 'completed',
            result: JSON.stringify(finalResult),
            completedTime: Date.now()
        });
        
        // Publish completion event
        await redis.publish('job:completed', JSON.stringify({ jobId, status: 'completed' }));
        
        console.log(`[${jobId}] Analysis completed successfully`);
        
    } catch (error) {
        console.error(`[${jobId}] Analysis failed:`, error);
        
        // Update job with error
        await redis.hset(`job:${jobId}`, {
            status: 'failed',
            error: error.message,
            failedTime: Date.now()
        });
        
        // Publish failure event
        await redis.publish('job:completed', JSON.stringify({ 
            jobId, 
            status: 'failed', 
            error: error.message 
        }));
    } finally {
        // Remove from active jobs
        activeJobs.delete(jobId);
    }
}

/**
 * Run basic REVENG analysis
 */
async function runRevengAnalysis(filePath, options) {
    return new Promise((resolve, reject) => {
        const args = [config.analyzerPath, filePath];
        
        // Add options as command line arguments
        if (options.outputFormat) {
            args.push('--output-format', options.outputFormat);
        }
        if (options.analysisDepth) {
            args.push('--analysis-depth', options.analysisDepth);
        }
        
        const process = spawn(config.pythonPath, args, {
            stdio: ['pipe', 'pipe', 'pipe'],
            timeout: config.maxJobTime
        });
        
        let stdout = '';
        let stderr = '';
        
        process.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        
        process.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        process.on('close', (code) => {
            if (code === 0) {
                try {
                    // Try to parse JSON output
                    const result = JSON.parse(stdout);
                    resolve(result);
                } catch (parseError) {
                    // If not JSON, return raw output
                    resolve({ output: stdout, stderr });
                }
            } else {
                reject(new Error(`REVENG analysis failed with code ${code}: ${stderr}`));
            }
        });
        
        process.on('error', (error) => {
            reject(new Error(`Failed to start REVENG analysis: ${error.message}`));
        });
    });
}

/**
 * Run enhanced AI analysis
 */
async function runEnhancedAnalysis(filePath, revengResult, options) {
    try {
        const enhancedResults = {};
        
        // Corporate exposure analysis
        if (options.corporateExposure) {
            const response = await axios.post(`${config.aiServiceUrl}/analyze/corporate-exposure`, {
                code: revengResult.decompiled_code || '',
                scan_type: 'credentials'
            }, { timeout: 300000 }); // 5 minutes
            
            enhancedResults.corporateExposure = response.data.result;
        }
        
        // Vulnerability analysis
        if (options.vulnerabilityAnalysis) {
            const response = await axios.post(`${config.aiServiceUrl}/analyze/vulnerabilities`, {
                code: revengResult.decompiled_code || '',
                vuln_type: 'memory'
            }, { timeout: 300000 });
            
            enhancedResults.vulnerabilities = response.data.result;
        }
        
        // Threat intelligence analysis
        if (options.threatIntelligence && revengResult.indicators) {
            const response = await axios.post(`${config.aiServiceUrl}/analyze/threat-intelligence`, {
                indicators: revengResult.indicators,
                analysis_type: 'apt_correlation'
            }, { timeout: 300000 });
            
            enhancedResults.threatIntelligence = response.data.result;
        }
        
        // Generate demonstration if requested
        if (options.generateDemo) {
            const response = await axios.post(`${config.aiServiceUrl}/generate/demonstration`, {
                analysis_result: { reveng: revengResult, enhanced: enhancedResults },
                demo_type: 'executive_dashboard'
            }, { timeout: 300000 });
            
            enhancedResults.demonstration = response.data.result;
        }
        
        return enhancedResults;
        
    } catch (error) {
        console.error('Enhanced analysis failed:', error.message);
        return { error: error.message };
    }
}

/**
 * Job queue processor
 */
async function processJobQueue() {
    console.log('Starting job queue processor...');
    
    while (true) {
        try {
            // Check if we have capacity for more jobs
            if (activeJobs.size >= config.workerConcurrency) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                continue;
            }
            
            // Get next job from queue
            const jobData = await redis.brpop('analysis:queue', 5);
            
            if (jobData) {
                const [, jobJson] = jobData;
                const job = JSON.parse(jobJson);
                
                // Add to active jobs
                activeJobs.set(job.jobId, job);
                
                // Process job asynchronously
                processAnalysisJob(job).catch(error => {
                    console.error(`Unhandled error in job ${job.jobId}:`, error);
                });
            }
            
        } catch (error) {
            console.error('Error in job queue processor:', error);
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
}

/**
 * Graceful shutdown handler
 */
process.on('SIGTERM', async () => {
    console.log('Received SIGTERM, shutting down gracefully...');
    
    // Wait for active jobs to complete (with timeout)
    const shutdownTimeout = 30000; // 30 seconds
    const startTime = Date.now();
    
    while (activeJobs.size > 0 && (Date.now() - startTime) < shutdownTimeout) {
        console.log(`Waiting for ${activeJobs.size} active jobs to complete...`);
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    if (activeJobs.size > 0) {
        console.log(`Force terminating with ${activeJobs.size} active jobs`);
    }
    
    redis.disconnect();
    process.exit(0);
});

// Start the worker
async function start() {
    try {
        // Test Redis connection
        await redis.ping();
        console.log('Connected to Redis');
        
        // Test AI service connection
        try {
            await axios.get(`${config.aiServiceUrl}/health`, { timeout: 5000 });
            console.log('Connected to AI service');
        } catch (error) {
            console.warn('AI service not available, enhanced analysis will be disabled');
        }
        
        // Start HTTP server for health checks
        app.listen(config.port, () => {
            console.log(`Analysis worker health endpoint listening on port ${config.port}`);
        });
        
        // Start job processing
        processJobQueue();
        
    } catch (error) {
        console.error('Failed to start worker:', error);
        process.exit(1);
    }
}

start();