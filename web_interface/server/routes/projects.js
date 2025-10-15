/**
 * Projects Routes
 * ===============
 * 
 * Project management endpoints for organizing analyses and collaboration
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

// In-memory project store (in production, this would be a database)
const projects = new Map();

/**
 * GET /api/projects
 * Get user projects
 */
router.get('/', async (req, res) => {
  try {
    const userProjects = [];
    
    for (const [id, project] of projects) {
      if (project.ownerId === req.user.id || 
          project.members.includes(req.user.id) || 
          project.isPublic) {
        userProjects.push({
          id: project.id,
          name: project.name,
          description: project.description,
          isPublic: project.isPublic,
          ownerId: project.ownerId,
          createdAt: project.createdAt,
          updatedAt: project.updatedAt,
          analysisCount: project.analyses.length,
          memberCount: project.members.length + 1, // +1 for owner
          isOwner: project.ownerId === req.user.id
        });
      }
    }

    // Sort by updated date (most recent first)
    userProjects.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

    res.json({
      success: true,
      projects: userProjects
    });

  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({
      error: 'Failed to get projects',
      message: error.message
    });
  }
});

/**
 * POST /api/projects
 * Create new project
 */
router.post('/', async (req, res) => {
  try {
    const { name, description, isPublic } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Project name is required'
      });
    }

    const projectId = uuidv4();
    const project = {
      id: projectId,
      name: name.trim(),
      description: description || '',
      isPublic: Boolean(isPublic),
      ownerId: req.user.id,
      members: [],
      analyses: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    projects.set(projectId, project);

    res.status(201).json({
      success: true,
      message: 'Project created successfully',
      project: {
        id: project.id,
        name: project.name,
        description: project.description,
        isPublic: project.isPublic,
        ownerId: project.ownerId,
        createdAt: project.createdAt,
        updatedAt: project.updatedAt,
        analysisCount: 0,
        memberCount: 1,
        isOwner: true
      }
    });

  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({
      error: 'Failed to create project',
      message: error.message
    });
  }
});

/**
 * GET /api/projects/:id
 * Get project details
 */
router.get('/:id', async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = projects.get(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The specified project does not exist'
      });
    }

    // Check access permissions
    if (project.ownerId !== req.user.id && 
        !project.members.includes(req.user.id) && 
        !project.isPublic) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to access this project'
      });
    }

    res.json({
      success: true,
      project: {
        id: project.id,
        name: project.name,
        description: project.description,
        isPublic: project.isPublic,
        ownerId: project.ownerId,
        members: project.members,
        analyses: project.analyses,
        createdAt: project.createdAt,
        updatedAt: project.updatedAt,
        isOwner: project.ownerId === req.user.id
      }
    });

  } catch (error) {
    console.error('Get project error:', error);
    res.status(500).json({
      error: 'Failed to get project',
      message: error.message
    });
  }
});

/**
 * PUT /api/projects/:id
 * Update project
 */
router.put('/:id', async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = projects.get(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The specified project does not exist'
      });
    }

    // Only owner can update project
    if (project.ownerId !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only the project owner can update the project'
      });
    }

    const { name, description, isPublic } = req.body;

    if (name !== undefined) {
      if (!name.trim()) {
        return res.status(400).json({
          error: 'Invalid input',
          message: 'Project name cannot be empty'
        });
      }
      project.name = name.trim();
    }

    if (description !== undefined) {
      project.description = description;
    }

    if (isPublic !== undefined) {
      project.isPublic = Boolean(isPublic);
    }

    project.updatedAt = new Date().toISOString();

    res.json({
      success: true,
      message: 'Project updated successfully',
      project: {
        id: project.id,
        name: project.name,
        description: project.description,
        isPublic: project.isPublic,
        updatedAt: project.updatedAt
      }
    });

  } catch (error) {
    console.error('Update project error:', error);
    res.status(500).json({
      error: 'Failed to update project',
      message: error.message
    });
  }
});

/**
 * DELETE /api/projects/:id
 * Delete project
 */
router.delete('/:id', async (req, res) => {
  try {
    const projectId = req.params.id;
    const project = projects.get(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The specified project does not exist'
      });
    }

    // Only owner can delete project
    if (project.ownerId !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only the project owner can delete the project'
      });
    }

    projects.delete(projectId);

    res.json({
      success: true,
      message: 'Project deleted successfully',
      projectId: projectId
    });

  } catch (error) {
    console.error('Delete project error:', error);
    res.status(500).json({
      error: 'Failed to delete project',
      message: error.message
    });
  }
});

/**
 * POST /api/projects/:id/members
 * Add member to project
 */
router.post('/:id/members', async (req, res) => {
  try {
    const projectId = req.params.id;
    const { userId } = req.body;
    const project = projects.get(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The specified project does not exist'
      });
    }

    // Only owner can add members
    if (project.ownerId !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only the project owner can add members'
      });
    }

    if (!userId) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'User ID is required'
      });
    }

    // Check if user is already a member
    if (project.members.includes(userId) || project.ownerId === userId) {
      return res.status(400).json({
        error: 'User already member',
        message: 'User is already a member of this project'
      });
    }

    project.members.push(userId);
    project.updatedAt = new Date().toISOString();

    res.json({
      success: true,
      message: 'Member added successfully',
      members: project.members
    });

  } catch (error) {
    console.error('Add member error:', error);
    res.status(500).json({
      error: 'Failed to add member',
      message: error.message
    });
  }
});

/**
 * DELETE /api/projects/:id/members/:userId
 * Remove member from project
 */
router.delete('/:id/members/:userId', async (req, res) => {
  try {
    const projectId = req.params.id;
    const userId = req.params.userId;
    const project = projects.get(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The specified project does not exist'
      });
    }

    // Only owner can remove members (or user can remove themselves)
    if (project.ownerId !== req.user.id && userId !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'Only the project owner or the user themselves can remove membership'
      });
    }

    const memberIndex = project.members.indexOf(userId);
    if (memberIndex === -1) {
      return res.status(404).json({
        error: 'Member not found',
        message: 'User is not a member of this project'
      });
    }

    project.members.splice(memberIndex, 1);
    project.updatedAt = new Date().toISOString();

    res.json({
      success: true,
      message: 'Member removed successfully',
      members: project.members
    });

  } catch (error) {
    console.error('Remove member error:', error);
    res.status(500).json({
      error: 'Failed to remove member',
      message: error.message
    });
  }
});

/**
 * POST /api/projects/:id/analyses
 * Add analysis to project
 */
router.post('/:id/analyses', async (req, res) => {
  try {
    const projectId = req.params.id;
    const { analysisId } = req.body;
    const project = projects.get(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The specified project does not exist'
      });
    }

    // Check if user has access to project
    if (project.ownerId !== req.user.id && !project.members.includes(req.user.id)) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to add analyses to this project'
      });
    }

    if (!analysisId) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Analysis ID is required'
      });
    }

    // Check if analysis is already in project
    if (project.analyses.includes(analysisId)) {
      return res.status(400).json({
        error: 'Analysis already in project',
        message: 'Analysis is already part of this project'
      });
    }

    project.analyses.push(analysisId);
    project.updatedAt = new Date().toISOString();

    res.json({
      success: true,
      message: 'Analysis added to project successfully',
      analyses: project.analyses
    });

  } catch (error) {
    console.error('Add analysis to project error:', error);
    res.status(500).json({
      error: 'Failed to add analysis to project',
      message: error.message
    });
  }
});

/**
 * DELETE /api/projects/:id/analyses/:analysisId
 * Remove analysis from project
 */
router.delete('/:id/analyses/:analysisId', async (req, res) => {
  try {
    const projectId = req.params.id;
    const analysisId = req.params.analysisId;
    const project = projects.get(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The specified project does not exist'
      });
    }

    // Check if user has access to project
    if (project.ownerId !== req.user.id && !project.members.includes(req.user.id)) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to remove analyses from this project'
      });
    }

    const analysisIndex = project.analyses.indexOf(analysisId);
    if (analysisIndex === -1) {
      return res.status(404).json({
        error: 'Analysis not found',
        message: 'Analysis is not part of this project'
      });
    }

    project.analyses.splice(analysisIndex, 1);
    project.updatedAt = new Date().toISOString();

    res.json({
      success: true,
      message: 'Analysis removed from project successfully',
      analyses: project.analyses
    });

  } catch (error) {
    console.error('Remove analysis from project error:', error);
    res.status(500).json({
      error: 'Failed to remove analysis from project',
      message: error.message
    });
  }
});

module.exports = router;