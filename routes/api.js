const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const axios = require('axios');
const { db } = require('../handlers/db.js');

// Constants
const API_VERSION = 'v1';
const BASE_PATH = `/api/${API_VERSION}`;
const SALT_ROUNDS = 10;

/**
 * Standard response formatter for consistent API responses
 * @param {boolean} success - Whether the operation was successful
 * @param {object|array|null} data - The data to return
 * @param {string|null} message - A message to include in the response
 * @param {number} statusCode - HTTP status code
 * @returns {object} Formatted response object
 */
const formatResponse = (success, data = null, message = null, statusCode = 200) => {
  const response = {
    success,
    statusCode,
    timestamp: new Date().toISOString()
  };

  if (data !== null) response.data = data;
  if (message !== null) response.message = message;
  
  return response;
};

/**
 * Error handler middleware
 */
const errorHandler = (err, req, res, next) => {
  console.error('API Error:', err);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal server error';
  
  res.status(statusCode).json(formatResponse(false, null, message, statusCode));
};

/**
 * API key validation middleware
 */
async function validateApiKey(req, res, next) {
  try {
    const apiKey = req.headers['x-api-key'] || req.query['key'];

    if (!apiKey) {
      return res.status(401).json(formatResponse(false, null, 'API key is required', 401));
    }

    const apiKeys = await db.get('apiKeys') || [];
    const validKey = apiKeys.find(key => key.key === apiKey);

    if (!validKey) {
      return res.status(401).json(formatResponse(false, null, 'Invalid API key', 401));
    }

    req.apiKey = validKey;
    next();
  } catch (error) {
    next(error);
  }
}

// Apply error handler to all routes
router.use(errorHandler);

/**
 * =========================
 * ===== API DOCUMENTATION
 * =========================
 */

// API Documentation route
router.get('/api', (req, res) => {
  res.json(formatResponse(true, {
    name: 'PowerPort API',
    version: API_VERSION,
    documentation: `/api/docs`,
    endpoints: [
      { path: `${BASE_PATH}/users`, methods: ['GET', 'POST'], description: 'Manage users' },
      { path: `${BASE_PATH}/users/:id`, methods: ['GET', 'PATCH', 'DELETE'], description: 'Get, update or delete user' },
      { path: `${BASE_PATH}/instances`, methods: ['GET', 'POST'], description: 'Manage instances' },
      { path: `${BASE_PATH}/instances/deploy`, methods: ['POST'], description: 'Deploy a new instance' },
      { path: `${BASE_PATH}/nodes`, methods: ['GET', 'POST'], description: 'Manage nodes' }
    ]
  }, 'API documentation'));
});

// API Documentation detailed route
router.get('/api/docs', (req, res) => {
  res.json(formatResponse(true, {
    name: 'PowerPort API Documentation',
    version: API_VERSION,
    baseUrl: BASE_PATH,
    authentication: 'API key required in X-API-Key header or as a query parameter "key"',
    endpoints: {
      users: {
        getAll: {
          path: `${BASE_PATH}/users`,
          method: 'GET',
          description: 'Get all users',
          authentication: 'Required',
          parameters: {},
          responses: {
            200: { description: 'Success', schema: { users: 'array' } },
            401: { description: 'Unauthorized' },
            500: { description: 'Server error' }
          }
        },
        // Add more detailed endpoint documentation
      },
      // Add more endpoint categories
    }
  }, 'Detailed API documentation'));
});

/**
 * =========================
 * ===== USER ENDPOINTS
 * =========================
 */

// Get all users
router.get(`${BASE_PATH}/users`, validateApiKey, async (req, res, next) => {
  try {
    const users = await db.get('users') || [];
    const sanitizedUsers = users.map(({ password, resetToken, ...user }) => user);
    res.json(formatResponse(true, sanitizedUsers));
  } catch (error) {
    next(error);
  }
});

// Get user by ID
router.get(`${BASE_PATH}/users/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    const users = await db.get('users') || [];
    const user = users.find(user => user.userId === id);
    
    if (!user) {
      return res.status(404).json(formatResponse(false, null, 'User  not found', 404));
    }
    
    const { password, resetToken, ...sanitizedUser  } = user;
    res.json(formatResponse(true, sanitizedUser ));
  } catch (error) {
    next(error);
  }
});

// Lookup user by email or username
router.get(`${BASE_PATH}/users/lookup`, validateApiKey, async (req, res, next) => {
  try {
    const { type, value } = req.query;

    if (!type || !value) {
      return res.status(400).json(formatResponse(false, null, 'Type and value parameters are required', 400));
    }

    if (type !== 'email' && type !== 'username') {
      return res.status(400).json(formatResponse(false, null, 'Type must be "email" or "username"', 400));
    }

    const users = await db.get('users') || [];
    const user = users.find(user => user[type] === value);
    
    if (!user) {
      return res.status(404).json(formatResponse(false, null, 'User  not found', 404));
    }
    
    const { password, resetToken, ...sanitizedUser  } = user;
    res.json(formatResponse(true, sanitizedUser ));
  } catch (error) {
    next(error);
  }
});

// Create user
router.post(`${BASE_PATH}/users`, validateApiKey, async (req, res, next) => {
  try {
    const { username, email, password, admin = false } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json(formatResponse(false, null, 'Username, email, and password are required', 400));
    }

    const users = await db.get('users') || [];
    const userExists = users.some(user => user.username === username || user.email === email);

    if (userExists) {
      return res.status(409).json(formatResponse(false, null, 'User  with this username or email already exists', 409));
    }

    const userId = uuidv4();
    const newUser  = {
      userId,
      username,
      email,
      password: await bcrypt.hash(password, SALT_ROUNDS),
      accessTo: [],
      admin: Boolean(admin),
      createdAt: new Date().toISOString()
    };

    users.push(newUser );
    await db.set('users', users);

    const { password: _, ...sanitizedUser  } = newUser ;
    res.status(201).json(formatResponse(true, sanitizedUser , 'User  created successfully', 201));
  } catch (error) {
    next(error);
  }
});

// Update user
router.patch(`${BASE_PATH}/users/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    
    delete updateData.password;
    delete updateData.userId;
    
    const users = await db.get('users') || [];
    const userIndex = users.findIndex(user => user.userId === id);
    
    if (userIndex === -1) {
      return res.status(404).json(formatResponse(false, null, 'User  not found', 404));
    }
    
    users[userIndex] = { ...users[userIndex], ...updateData, updatedAt: new Date().toISOString() };
    await db.set('users', users);
    
    const { password, resetToken, ...sanitizedUser  } = users[userIndex];
    res.json(formatResponse(true, sanitizedUser , 'User  updated successfully'));
  } catch (error) {
    next(error);
  }
});

// Change user password
router.post(`${BASE_PATH}/users/:id/change-password`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { newPassword } = req.body;
    
    if (!newPassword) {
      return res.status(400).json(formatResponse(false, null, 'New password is required', 400));
    }
    
    const users = await db.get('users') || [];
    const userIndex = users.findIndex(user => user.userId === id);
    
    if (userIndex === -1) {
      return res.status(404).json(formatResponse(false, null, 'User  not found', 404));
    }
    
    users[userIndex].password = await bcrypt.hash(newPassword, SALT_ROUNDS);
    users[userIndex].updatedAt = new Date().toISOString();
    await db.set('users', users);
    
    res.json(formatResponse(true, null, 'Password changed successfully'));
  } catch (error) {
    next(error);
  }
});

// Delete user
router.delete(`${BASE_PATH}/users/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const users = await db.get('users') || [];
    const userIndex = users.findIndex(user => user.userId === id);
    
    if (userIndex === -1) {
      return res.status(404).json(formatResponse(false, null, 'User  not found', 404));
    }
    
    users.splice(userIndex, 1);
    await db.set('users', users);
    
    res.json(formatResponse(true, null, 'User  deleted successfully'));
  } catch (error) {
    next(error);
  }
});

/**
 * =========================
 * ===== INSTANCE ENDPOINTS
 * =========================
 */

// Get all instances
router.get(`${BASE_PATH}/instances`, validateApiKey, async (req, res, next) => {
  try {
    const instances = await db.get('instances') || [];
    res.json(formatResponse(true, instances));
  } catch (error) {
    next(error);
  }
});

// Get instance by ID
router.get(`${BASE_PATH}/instances/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    const instance = await db.get(`${id}_instance`);
    
    if (!instance) {
      return res.status(404).json(formatResponse(false, null, 'Instance not found', 404));
    }
    
    res.json(formatResponse(true, instance));
  } catch (error) {
    next(error);
  }
});

// Get instances by user ID
router.get(`${BASE_PATH}/users/:userId/instances`, validateApiKey, async (req, res, next) => {
  try {
    const { userId } = req.params;
    
    const users = await db.get('users') || [];
    const userExists = users.some(user => user.userId === userId);
    
    if (!userExists) {
      return res.status(404).json(formatResponse(false, null, 'User  not found', 404));
    }
    
    const userInstances = await db.get(`${userId}_instances`) || [];
    res.json(formatResponse(true, userInstances));
  } catch (error) {
    next(error);
  }
});

// Create instance (deploy)
router.post(`${BASE_PATH}/instances/deploy`, validateApiKey, async (req, res, next) => {
  try {
    const { image, imagename, memory, cpu, disk, ports, nodeId, name, userId, primary, variables } = req.body;

    if (!image || !memory || !cpu || !ports || !nodeId || !name || !userId || !primary) {
      return res.status(400).json(formatResponse(false, null, 'Missing required parameters', 400));
    }

    const users = await db.get('users') || [];
    const userExists = users.some(user => user.userId === userId);
    
    if (!userExists) {
      return res.status(404).json(formatResponse(false, null, 'User  not found', 404));
    }

    const node = await db.get(`${nodeId}_node`);
    if (!node) {
      return res.status(404).json(formatResponse(false, null, 'Node not found', 404));
    }

    const Id = uuidv4().split('-')[0];

    try {
      const requestData = await prepareRequestData(
        image,
        memory,
        cpu,
        ports,
        name,
        node,
        Id,
        variables,
        imagename,
      );

      const response = await axios(requestData);

      if (response.status === 201) {
        await updateDatabaseWithNewInstance(
          response.data,
          userId,
          node,
          image,
          memory,
          disk,
          cpu,
          ports,
          primary,
          name,
          Id,
          imagename,
        );

        return res.status(201).json(formatResponse(true, {
          instanceId: Id,
          containerId: response.data.containerId,
          volumeId: response.data.volumeId,
        }, 'Instance created successfully', 201));
      } else {
        return res.status(response.status).json(formatResponse(false, response.data, 'Failed to deploy container', response.status));
      }
    } catch (error) {
      console.error('Error deploying instance:', error);
      return res.status(500).json(formatResponse(false, error.response ? error.response.data : null, 'Failed to create container', 500));
    }
  } catch (error) {
    next(error);
  }
});

// Delete instance
router.delete(`${BASE_PATH}/instances/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const instance = await db.get(`${id}_instance`);
    if (!instance) {
      return res.status(404).json(formatResponse(false, null, 'Instance not found', 404));
    }
    
    await deleteInstance(instance);
    res.json(formatResponse(true, null, 'Instance deleted successfully'));
  } catch (error) {
    next(error);
  }
});

// Suspend instance
router.post(`${BASE_PATH}/instances/:id/suspend`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const instance = await db.get(`${id}_instance`);
    if (!instance) {
      return res.status(404).json(formatResponse(false, null, 'Instance not found', 404));
    }

    instance.suspended = true;
    await db.set(`${id}_instance`, instance);

    let instances = await db.get('instances') || [];
    let instanceToSuspend = instances.find(obj => obj.ContainerId === instance.ContainerId);
    if (instanceToSuspend) {
      instanceToSuspend.suspended = true;
    }

    await db.set('instances', instances);

    res.json(formatResponse(true, null, `Instance ${id} has been suspended`));
  } catch (error) {
    next(error);
  }
});

// Unsuspend instance
router.post(`${BASE_PATH}/instances/:id/unsuspend`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const instance = await db.get(`${id}_instance`);
    if (!instance) {
      return res.status(404).json(formatResponse(false, null, 'Instance not found', 404));
    }

    instance.suspended = false;
    await db.set(`${id}_instance`, instance);

    let instances = await db.get('instances') || [];
    let instanceToUnsuspend = instances.find(obj => obj.ContainerId === instance.ContainerId);
    if (instanceToUnsuspend) {
      instanceToUnsuspend.suspended = false;
    }

    await db.set('instances', instances);

    res.json(formatResponse(true, null, `Instance ${id} has been unsuspended`));
  } catch (error) {
    next(error);
  }
});

/**
 * =========================
 * ===== NODE ENDPOINTS
 * =========================
 */

// Get all nodes
router.get(`${BASE_PATH}/nodes`, validateApiKey, async (req, res, next) => {
  try {
    const nodes = await db.get('nodes') || [];
    const nodeDetails = await Promise.all(nodes.map(id => db.get(`${id}_node`)));
    res.json(formatResponse(true, nodeDetails));
  } catch (error) {
    next(error);
  }
});

// Get node by ID
router.get(`${BASE_PATH}/nodes/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    const node = await db.get(`${id}_node`);
    
    if (!node) {
      return res.status(404).json(formatResponse(false, null, 'Node not found', 404));
    }
    
    res.json(formatResponse(true, node));
  } catch (error) {
    next(error);
  }
});

// Create node
router.post(`${BASE_PATH}/nodes`, validateApiKey, async (req, res, next) => {
  try {
    const { name, tags, ram, disk, processor, address, port } = req.body;

    if (!name || !tags || !ram || !disk || !processor || !address || !port) {
      return res.status(400).json(formatResponse(false, null, 'Missing required parameters', 400));
    }

    const nodeId = uuidv4();
    const configureKey = uuidv4();
    
    const node = {
      id: nodeId,
      name,
      tags,
      ram,
      disk,
      processor,
      address,
      port,
      apiKey: null,
      configureKey,
      status: 'Unconfigured',
      createdAt: new Date().toISOString()
    };

    await db.set(`${nodeId}_node`, node);
    const updatedNode = await checkNodeStatus(node);

    const nodes = await db.get('nodes') || [];
    nodes.push(nodeId);
    await db.set('nodes', nodes);

    res.status(201).json(formatResponse(true, updatedNode, 'Node created successfully', 201));
  } catch (error) {
    next(error);
  }
});
// Check node status (dummy placeholder)
async function checkNodeStatus(node) {
  // Implement actual status check via ping or API call
  return { ...node, status: 'Online' };
}

/*end of main
/**
 * Checks the operational status of a node
 * @param {object} node - Node object
 * @returns {Promise<object>} Updated node object
 */
async function checkNodeStatus(node) {
  try {
    const RequestData = {
      method: 'get',
      url: `http://${node.address}:${node.port}/`,
      auth: {
        username: 'Skyport',
        password: node.apiKey
      },
      headers: { 
        'Content-Type': 'application/json'
      },
      timeout: 5000 // Add timeout to prevent long waits
    };
    
    const response = await axios(RequestData);
    const { versionFamily, versionRelease, online, remote, docker } = response.data;

    node.status = 'Online';
    node.versionFamily = versionFamily;
    node.versionRelease = versionRelease;
    node.remote = remote;
    node.docker = docker;
    node.lastChecked = new Date().toISOString();

    await db.set(`${node.id}_node`, node);
    return node;
  } catch (error) {
    node.status = 'Offline';
    node.lastChecked = new Date().toISOString();
    node.lastError = error.message;
    
    await db.set(`${node.id}_node`, node);
    return node;
  }
}

// ===== LEGACY API ROUTES =====
// These routes are maintained for backward compatibility
// They should be considered deprecated and will be removed in future versions

// Legacy routes - redirect to new versioned endpoints with a deprecation warning
router.get('/api/users', validateApiKey, (req, res) => {
  res.set('X-Deprecated-API', 'This endpoint is deprecated. Please use ' + BASE_PATH + '/users instead.');
  res.redirect(307, BASE_PATH + '/users');
});

// Add more legacy route redirects as needed

module.exports = router;
