/*

PROPRIETARY RIGHTS NOTICE

THIS SOFTWARE PRODUCT IS THE PROPRIETARY PROPERTY OF HYDREN, 
149 NEW MONTGOMERY ST 4TH FLOOR, SAN FRANCISCO, CA 94105, UNITED STATES ("HYDREN, INC.").

ALL RIGHT, TITLE, AND INTEREST IN AND TO THIS SOFTWARE PRODUCT AND ANY 
AND ALL COPIES THEREOF, INCLUDING BUT NOT LIMITED TO ALL INTELLECTUAL 
PROPERTY RIGHTS, ARE AND SHALL REMAIN THE EXCLUSIVE PROPERTY OF OWNER.

THIS SOFTWARE PRODUCT IS PROTECTED BY COPYRIGHT LAWS AND INTERNATIONAL 
COPYRIGHT TREATIES, AS WELL AS OTHER INTELLECTUAL PROPERTY LAWS AND 
TREATIES.

UNAUTHORIZED REPRODUCTION, DISPLAY, DISTRIBUTION, OR USE OF THIS SOFTWARE 
PRODUCT OR ANY PORTION THEREOF MAY RESULT IN SEVERE CIVIL AND CRIMINAL 
PENALTIES, AND WILL BE PROSECUTED TO THE MAXIMUM EXTENT POSSIBLE UNDER LAW.

© 2025 Hydren, INC. ALL RIGHTS RESERVED.

*/ 


const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bodyParser = require('body-parser');
const CatLoggr = require('cat-loggr');
const fs = require('node:fs');
const path = require('path');
const chalk = require('chalk');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const expressWs = require('express-ws');
const sqlite = require("better-sqlite3");
const SqliteStore = require("better-sqlite3-session-store")(session);

const config = require('./config.json');
const ascii = fs.readFileSync('./handlers/ascii.txt', 'utf8');
const { db } = require('./handlers/db.js');
const translationMiddleware = require('./handlers/translation');
const { loadPlugins } = require('./plugins/loadPls.js');
const { init } = require('./handlers/init.js');
const theme = require('./storage/theme.json');

const app = express();
expressWs(app);

const log = new CatLoggr();
const sessionstorage = new sqlite("sessions.db");

// Load plugins config
let plugins = loadPlugins(path.join(__dirname, './plugins'));
plugins = Object.values(plugins).map(plugin => plugin.config);

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(translationMiddleware);

const postRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 6,
  message: 'Too many requests, please try again later'
});

app.use((req, res, next) => {
  if (req.method === 'POST') {
    postRateLimiter(req, res, next);
  } else {
    next();
  }
});

app.set('view engine', 'ejs');
app.use(session({
  store: new SqliteStore({
    client: sessionstorage,
    expired: { clear: true, intervalMs: 9000000 }
  }),
  secret: "secret",
  resave: true,
  saveUninitialized: true
}));

app.use(async (req, res, next) => {
  try {
    const settings = await db.get('settings');
    res.locals.languages = getlanguages();
    res.locals.ogTitle = config.ogTitle;
    res.locals.ogDescription = config.ogDescription;
    res.locals.footer = settings?.footer || '';
    res.locals.theme = theme;
    next();
  } catch (error) {
    console.error('Error fetching settings:', error);
    next(error);
  }
});

if (config.mode === 'production') {
  app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '5');
    next();
  });

  app.use('/assets', (req, res, next) => {
    res.setHeader('Cache-Control', 'public, max-age=1');
    next();
  });
}

app.use(passport.initialize());
app.use(passport.session());

// Plugins
const pluginRoutes = require('./plugins/pluginmanager.js');
app.use("/", pluginRoutes);

const pluginDir = path.join(__dirname, 'plugins');
const PluginViewsDir = fs.readdirSync(pluginDir).map(addonName => path.join(pluginDir, addonName, 'views'));
app.set('views', [path.join(__dirname, 'views'), ...PluginViewsDir]);

init(); // Initialize main logic

console.log(chalk.gray(ascii) + chalk.white(`version v${config.version}\n`));

// ---------------------
// /api welcome handler
// ---------------------
app.get('/api', (req, res) => {
  res.status(200).json({
    success: true,
    statusCode: 200,
    timestamp: new Date().toISOString(),
    message: "Welcome to the PowerPort API",
    documentation: "/api/docs",
    endpoints: [
      { path: "/api/users", method: "GET", description: "Get all users" },
      { path: "/api/instances", method: "GET", description: "Get all instances" },
      { path: "/api/nodes", method: "GET", description: "Get all nodes" },
      { path: "/api/images", method: "GET", description: "Get all images" }
    ]
  });
});

// Language setter
app.get('/setLanguage', async (req, res) => {
  const lang = req.query.lang;
  if (lang && (await getlanguages()).includes(lang)) {
    res.cookie('lang', lang, { maxAge: 90000000, httpOnly: true, sameSite: 'strict' });
    if (req.user) req.user.lang = lang;
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// Load API routes first
const apiRoutes = require('./routes/api.js');
app.use("/", apiRoutes);

// Load all other routes except api.js
const routesDir = path.join(__dirname, 'routes');
function loadRoutes(directory) {
  fs.readdirSync(directory).forEach(file => {
    const fullPath = path.join(directory, file);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      loadRoutes(fullPath);
    } else if (stat.isFile() && path.extname(file) === '.js' && file !== 'api.js') {
      const route = require(fullPath);
      app.use("/", route);
    }
  });
}
loadRoutes(routesDir);

app.use(express.static('public'));

app.listen(config.port, () => log.info(`PowerPort is listening on port ${config.port}`));

// Catch-all 404 page
app.get('*', async function (req, res) {
  res.status(404).render('errors/404', {
    req,
    name: await db.get('name') || 'PowerPort',
    logo: await db.get('logo') || false
  });
});

// Helper functions
function getlanguages() {
  return fs.readdirSync(path.join(__dirname, 'lang')).map(file => file.split('.')[0]);
}

// Init project state
init();
