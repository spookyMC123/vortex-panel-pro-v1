const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { v4: uuid } = require('uuid');
const bcrypt = require('bcrypt');
const WebSocket = require('ws');
const axios = require('axios');
const { sendPasswordResetEmail } = require('../handlers/email.js');
const { logAudit } = require('../handlers/auditlog');
const { db } = require('../handlers/db.js');

// Constants
const API_VERSION = 'v1';
const BASE_PATH = `/api/${API_VERSION}`;
const saltRounds = 10;

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

  if (data) response.data = data;
  if (message) response.message = message;
  
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
    // Check for API key in header first, then query param
    const apiKey = req.headers['x-api-key'] || req.query['key'];

    if (!apiKey) {
      return res.status(401).json(formatResponse(false, null, 'API key is required', 401));
    }

    const apiKeys = await db.get('apiKeys') || [];
    const validKey = apiKeys.find(key => key.key === apiKey);

    if (!validKey) {
      return res.status(401).json(formatResponse(false, null, 'Invalid API key', 401));
    }

    // Add API key info to request for potential logging/auditing
    req.apiKey = validKey;
    next();
  } catch (error) {
    next(error);
  }
}

// Apply error handler to all routes
router.use(errorHandler);

// API Documentation route
router.get('/api', (req, res) => {
  res.json(formatResponse(true, {
    name: 'PowerPort API',
    version: API_VERSION,
    documentation: `/api/docs`,
    endpoints: [
      { path: `${BASE_PATH}/users`, methods: ['GET'], description: 'Get all users' },
      { path: `${BASE_PATH}/users/:id`, methods: ['GET'], description: 'Get user by ID' },
      { path: `${BASE_PATH}/instances`, methods: ['GET'], description: 'Get all instances' },
      { path: `${BASE_PATH}/instances/:id`, methods: ['GET'], description: 'Get instance by ID' },
      { path: `${BASE_PATH}/nodes`, methods: ['GET'], description: 'Get all nodes' },
      // Add more endpoint documentation here
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

// ===== USER ENDPOINTS =====

// Get all users
router.get(`${BASE_PATH}/users`, validateApiKey, async (req, res, next) => {
  try {
    const users = await db.get('users') || [];
    // Remove sensitive information
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
      return res.status(404).json(formatResponse(false, null, 'User not found', 404));
    }
    
    // Remove sensitive information
    const { password, resetToken, ...sanitizedUser } = user;
    res.json(formatResponse(true, sanitizedUser));
  } catch (error) {
    next(error);
  }
});

// Get user by email or username
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
      return res.status(404).json(formatResponse(false, null, 'User not found', 404));
    }
    
    // Remove sensitive information
    const { password, resetToken, ...sanitizedUser } = user;
    res.json(formatResponse(true, sanitizedUser));
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
      return res.status(409).json(formatResponse(false, null, 'User with this username or email already exists', 409));
    }

    const userId = uuidv4();
    const newUser = {
      userId,
      username,
      email,
      password: await bcrypt.hash(password, saltRounds),
      accessTo: [],
      admin: Boolean(admin),
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await db.set('users', users);

    // Remove sensitive information from response
    const { password: _, ...sanitizedUser } = newUser;
    res.status(201).json(formatResponse(true, sanitizedUser, 'User created successfully', 201));
  } catch (error) {
    next(error);
  }
});

// Update user
router.patch(`${BASE_PATH}/users/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    
    // Prevent updating sensitive fields directly
    delete updateData.password;
    delete updateData.userId;
    
    const users = await db.get('users') || [];
    const userIndex = users.findIndex(user => user.userId === id);
    
    if (userIndex === -1) {
      return res.status(404).json(formatResponse(false, null, 'User not found', 404));
    }
    
    // Update user data
    users[userIndex] = { ...users[userIndex], ...updateData, updatedAt: new Date().toISOString() };
    await db.set('users', users);
    
    // Remove sensitive information
    const { password, resetToken, ...sanitizedUser } = users[userIndex];
    res.json(formatResponse(true, sanitizedUser, 'User updated successfully'));
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
      return res.status(404).json(formatResponse(false, null, 'User not found', 404));
    }
    
    // Update password
    users[userIndex].password = await bcrypt.hash(newPassword, saltRounds);
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
      return res.status(404).json(formatResponse(false, null, 'User not found', 404));
    }
    
    // Remove user
    users.splice(userIndex, 1);
    await db.set('users', users);
    
    res.json(formatResponse(true, null, 'User deleted successfully'));
  } catch (error) {
    next(error);
  }
});

// ===== INSTANCE ENDPOINTS =====

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
    
    // Verify user exists
    const users = await db.get('users') || [];
    const userExists = users.some(user => user.userId === userId);
    
    if (!userExists) {
      return res.status(404).json(formatResponse(false, null, 'User not found', 404));
    }
    
    const userInstances = await db.get(`${userId}_instances`) || [];
    res.json(formatResponse(true, userInstances));
  } catch (error) {
    next(error);
  }
});

// Create instance
router.post(`${BASE_PATH}/instances`, validateApiKey, async (req, res, next) => {
  try {
    const { image, imagename, memory, cpu, disk, ports, nodeId, name, userId, primary, variables } = req.body;

    if (!image || !memory || !cpu || !ports || !nodeId || !name || !userId || !primary) {
      return res.status(400).json(formatResponse(false, null, 'Missing required parameters', 400));
    }

    // Verify user exists
    const users = await db.get('users') || [];
    const userExists = users.some(user => user.userId === userId);
    
    if (!userExists) {
      return res.status(404).json(formatResponse(false, null, 'User not found', 404));
    }

    // Verify node exists
    const node = await db.get(`${nodeId}_node`);
    if (!node) {
      return res.status(404).json(formatResponse(false, null, 'Node not found', 404));
    }

    const Id = uuid().split('-')[0];

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

// ===== NODE ENDPOINTS =====

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

// Delete node
router.delete(`${BASE_PATH}/nodes/:id`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const node = await db.get(`${id}_node`);
    if (!node) {
      return res.status(404).json(formatResponse(false, null, 'Node not found', 404));
    }
    
    const nodes = await db.get('nodes') || [];
    const newNodes = nodes.filter(nodeId => nodeId !== id);
    
    await db.set('nodes', newNodes);
    await db.delete(`${id}_node`);
    
    res.json(formatResponse(true, null, 'Node deleted successfully'));
  } catch (error) {
    next(error);
  }
});

// Get node configuration command
router.get(`${BASE_PATH}/nodes/:id/configure-command`, validateApiKey, async (req, res, next) => {
  try {
    const { id } = req.params;
    
    const node = await db.get(`${id}_node`);
    if (!node) {
      return res.status(404).json(formatResponse(false, null, 'Node not found', 404));
    }
    
    // Generate a new configure key
    const configureKey = uuidv4();
    
    // Update the node with the new configure key
    node.configureKey = configureKey;
    await db.set(`${id}_node`, node);
    
    // Construct the configuration command
    const panelUrl = `${req.protocol}://${req.get('host')}`;
    const configureCommand = `npm run configure -- --panel ${panelUrl} --key ${configureKey}`;
    
    res.json(formatResponse(true, {
      nodeId: id,
      configureCommand
    }));
  } catch (error) {
    next(error);
  }
});

// ===== IMAGE ENDPOINTS =====

// Get all images
router.get(`${BASE_PATH}/images`, validateApiKey, async (req, res, next) => {
  try {
    const images = await db.get('images') || [];
    res.json(formatResponse(true, images));
  } catch (error) {
    next(error);
  }
});

// Get panel name
router.get(`${BASE_PATH}/panel/name`, validateApiKey, async (req, res, next) => {
  try {
    const name = await db.get('name') || 'PowerPort';
    res.json(formatResponse(true, { name }));
  } catch (error) {
    next(error);
  }
});

// ===== WEBSOCKET ENDPOINTS =====

// Instance console WebSocket
router.ws(`${BASE_PATH}/instances/:id/console`, async (ws, req) => {
  try {
    // Validate API key for WebSocket
    const apiKey = req.query.key;
    if (!apiKey) {
      ws.close(1008, 'API key is required');
      return;
    }

    const apiKeys = await db.get('apiKeys') || [];
    const validKey = apiKeys.find(key => key.key === apiKey);
    if (!validKey) {
      ws.close(1008, 'Invalid API key');
      return;
    }

    const { id } = req.params;
    const instance = await db.get(`${id}_instance`);

    if (!instance || !id) {
      ws.close(1008, 'Invalid instance or ID');
      return;
    }

    const node = instance.Node;
    const socket = new WebSocket(`ws://${node.address}:${node.port}/exec/${instance.ContainerId}`);

    socket.onopen = () => {
      socket.send(JSON.stringify({ "event": "auth", "args": [node.apiKey] }));
    };

    socket.onmessage = msg => {
      ws.send(msg.data);
    };

    socket.onerror = (error) => {
      ws.send('\x1b[31;1mDaemon instance appears to be down');
    };

    socket.onclose = (event) => {};

    ws.onmessage = msg => {
      socket.send(msg.data);
    };

    ws.on('close', () => {
      socket.close();
    });
  } catch (error) {
    console.error('WebSocket error:', error);
    ws.close(1011, 'Internal server error');
  }
});

// ===== HELPER FUNCTIONS =====

/**
 * Generates a random code of specified length
 * @param {number} length - Length of the code to generate
 * @returns {string} Random code
 */
function generateRandomCode(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

/**
 * Deletes an instance and updates related database records
 * @param {object} instance - Instance object to delete
 * @returns {Promise<void>}
 */
async function deleteInstance(instance) {
  try {
    await axios.get(`http://Skyport:${instance.Node.apiKey}@${instance.Node.address}:${instance.Node.port}/instances/${instance.ContainerId}/delete`);
    
    // Update user's instances
    let userInstances = await db.get(`${instance.User}_instances`) || [];
    userInstances = userInstances.filter(obj => obj.ContainerId !== instance.ContainerId);
    await db.set(`${instance.User}_instances`, userInstances);
    
    // Update global instances
    let globalInstances = await db.get('instances') || [];
    globalInstances = globalInstances.filter(obj => obj.ContainerId !== instance.ContainerId);
    await db.set('instances', globalInstances);
    
    // Delete instance-specific data
    await db.delete(`${instance.ContainerId}_instance`);
  } catch (error) {
    console.error(`Error deleting instance ${instance.ContainerId}:`, error);
    throw error;
  }
}

/**
 * Updates database with new instance information
 * @param {object} responseData - Response data from instance creation
 * @param {string} userId - User ID
 * @param {object} node - Node object
 * @param {string} image - Image name
 * @param {number|string} memory - Memory allocation
 * @param {number|string} disk - Disk allocation
 * @param {number|string} cpu - CPU allocation
 * @param {string} ports - Port mappings
 * @param {string} primary - Primary port
 * @param {string} name - Instance name
 * @param {string} Id - Instance ID
 * @param {string} imagename - Image name
 * @returns {Promise<void>}
 */
async function updateDatabaseWithNewInstance(
  responseData,
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
) {
  const rawImages = await db.get('images');
  const imageData = rawImages.find(i => i.Name === imagename);

  let altImages = imageData ? imageData.AltImages : [];

  const instanceData = {
    Name: name,
    Id,
    Node: node,
    User: userId,
    ContainerId: responseData.containerId,
    VolumeId: Id,
    Memory: parseInt(memory),
    Disk: disk,
    Cpu: parseInt(cpu),
    Ports: ports,
    Primary: primary,
    Image: image,
    AltImages: altImages,
    StopCommand: imageData ? imageData.StopCommand : undefined,
    imageData,
    Env: responseData.Env,
    State: responseData.state,
    createdAt: new Date().toISOString()
  };

  const userInstances = (await db.get(`${userId}_instances`)) || [];
  userInstances.push(instanceData);
  await db.set(`${userId}_instances`, userInstances);

  const globalInstances = (await db.get('instances')) || [];
  globalInstances.push(instanceData);
  await db.set('instances', globalInstances);

  await db.set(`${Id}_instance`, instanceData);
}

/**
 * Prepares request data for instance creation
 * @param {string} image - Image name
 * @param {number|string} memory - Memory allocation
 * @param {number|string} cpu - CPU allocation
 * @param {string} ports - Port mappings
 * @param {string} name - Instance name
 * @param {object} node - Node object
 * @param {string} Id - Instance ID
 * @param {object} variables - Environment variables
 * @param {string} imagename - Image name
 * @returns {Promise<object>} Request data
 */
async function prepareRequestData(image, memory, cpu, ports, name, node, Id, variables, imagename) {
  const rawImages = await db.get('images');
  const imageData = rawImages.find(i => i.Name === imagename);

  const requestData = {
    method: 'post',
    url: `http://${node.address}:${node.port}/instances/create`,
    auth: {
      username: 'Skyport',
      password: node.apiKey,
    },
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      Name: name,
      Id,
      Image: image,
      Env: imageData ? imageData.Env : undefined,
      Scripts: imageData ? imageData.Scripts : undefined,
      Memory: memory ? parseInt(memory) : undefined,
      Cpu: cpu ? parseInt(cpu) : undefined,
      ExposedPorts: {},
      PortBindings: {},
      variables,
      AltImages: imageData ? imageData.AltImages : [],
      StopCommand: imageData ? imageData.StopCommand : undefined,
      imageData,
    },
  };

  if (ports) {
    ports.split(',').forEach(portMapping => {
      const [containerPort, hostPort] = portMapping.split(':');

      // Adds support for TCP
      const tcpKey = `${containerPort}/tcp`;
      if (!requestData.data.ExposedPorts[tcpKey]) {
        requestData.data.ExposedPorts[tcpKey] = {};
      }

      if (!requestData.data.PortBindings[tcpKey]) {
        requestData.data.PortBindings[tcpKey] = [{ HostPort: hostPort }];
      }

      // Adds support for UDP
      const udpKey = `${containerPort}/udp`;
      if (!requestData.data.ExposedPorts[udpKey]) {
        requestData.data.ExposedPorts[udpKey] = {};
      }

      if (!requestData.data.PortBindings[udpKey]) {
        requestData.data.PortBindings[udpKey] = [{ HostPort: hostPort }];
      }
    });
  }

  return requestData;
}

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
