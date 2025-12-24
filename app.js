const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');

const app = express();

const DATA_FILE = path.join(__dirname, 'data', 'data.json');
const DEFAULT_CATEGORIES = ['Robotique', 'IA', 'Theatre', 'Musique', 'Autre'];

/**
 * createEmptyData
 * ----------------
 * Creates and returns a default empty data structure.
 * This function is used when the data file does not exist or cannot be read.
 * It ensures that the application always has a valid structure to work with,
 * preventing 'undefined' errors when accessing arrays like students, activities, etc.
 */
function createEmptyData() {
  return {
    activities: [],      // List of all activities
    students: [],        // List of all registered students
    registrations: [],   // Links between students and activities
    clubs: [],           // List of clubs (Robotique, IA, etc.)
    clubMemberships: [], // Links between students and clubs
    admins: [],          // List of global administrators
    clubAdmins: []       // List of club-specific administrators
  };
}

/**
 * loadData
 * --------
 * Reads the data.json file from the disk and parses it.
 * If the file doesn't exist or is empty, it returns the default empty structure.
 * It also performs a "sanity check" to ensure all expected arrays exist,
 * initializing them to empty arrays if they are missing.
 *
 * Returns: The full data object.
 */
function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    return createEmptyData();
  }

  const raw = fs.readFileSync(DATA_FILE, 'utf8');
  if (!raw.trim()) {
    return createEmptyData();
  }

  try {
    const data = JSON.parse(raw);

    if (!Array.isArray(data.activities)) data.activities = [];
    if (!Array.isArray(data.students)) data.students = [];
    if (!Array.isArray(data.registrations)) data.registrations = [];
    if (!Array.isArray(data.clubs)) data.clubs = [];
    if (!Array.isArray(data.clubMemberships)) data.clubMemberships = [];
    if (!Array.isArray(data.admins)) data.admins = [];
    if (!Array.isArray(data.clubAdmins)) data.clubAdmins = [];

    return data;
  } catch (e) {
    return createEmptyData();
  }
}

/**
 * saveData
 * --------
 * Writes the current data object back to data.json.
 * It first checks if the directory exists and creates it if necessary.
 * Then it serializes the data to JSON with indentation (null, 2) for readability.
 *
 * @param {Object} data - The complete data object to save.
 */
function saveData(data) {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) {
    
    fs.mkdirSync(dir, { recursive: true });
  }

  const toSave = {
    activities: data.activities || [],
    students: data.students || [],
    registrations: data.registrations || [],
    clubs: data.clubs || [],
    clubMemberships: data.clubMemberships || [],
    admins: data.admins || [],
    clubAdmins: data.clubAdmins || []
  };

  fs.writeFileSync(DATA_FILE, JSON.stringify(toSave, null, 2), 'utf8');
}

/**
 * ensureInitialData
 * -----------------
 * Checked at server startup.
 * Ensures that there are at least some default clubs created if the list is empty.
 * This guarantees the application has its basic categories (Robotique, IA, etc.) ready.
 */
function ensureInitialData() {
  const data = loadData();

  if (!data.clubs || data.clubs.length === 0) {
    data.clubs = [
      { id: uuidv4(), name: 'Robotique' },
      { id: uuidv4(), name: 'IA' },
      { id: uuidv4(), name: 'Theatre' },
      { id: uuidv4(), name: 'Musique' }
    ];
  }

  if (!data.admins) {
    data.admins = [];
  }

  if (!data.clubAdmins) {
    data.clubAdmins = [];
  }

  saveData(data);
}

/**
 * getParticipantsForActivity
 * --------------------------
 * Helper function to retrieve all students registered for a specific activity.
 *
 * @param {Object} data - The full data object.
 * @param {string} activityId - The ID of the activity to check.
 * @returns {Array} - An array of objects, each containing { student, registration }.
 */
function getParticipantsForActivity(data, activityId) {
  const regs = data.registrations.filter(r => r.activityId === activityId);
  return regs
    .map(r => {
      const student = data.students.find(s => s.id === r.studentId);
      return { student, registration: r };
    })
    .filter(p => p.student);
}

// Middleware to protect admin routes
// Checks if the user has the 'isAdmin' flag in their session
/**
 * Middleware: requireAdmin
 * ------------------------
 * Protects routes that should only be accessible by a global administrator.
 * It checks the `req.session.isAdmin` flag.
 * If the user is not an admin:
 * 1. It saves the original URL in `req.session.returnTo` so they can be redirected back after login.
 * 2. It redirects them to the admin login page.
 */
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) {
    // If not admin, save the URL they wanted to visit
    req.session.returnTo = req.originalUrl;
    // Redirect to the admin login page
    return res.redirect('/admin/login');
  }
  // If admin, proceed to the requested route
  return next();
}

// Middleware to protect club admin routes
// Checks if the user is a club admin and has a specific club ID assigned
/**
 * Middleware: requireClubAdmin
 * ----------------------------
 * Protects routes for club administrators.
 * It checks if `req.session.isClubAdmin` is true AND if they have a `clubAdminClubId` assigned.
 * If not, it sends a 403 Forbidden response (access denied).
 */
function requireClubAdmin(req, res, next) {
  if (!req.session.isClubAdmin || !req.session.clubAdminClubId) {
    return res.status(403).send('Acces reserve a ladministrateur du club.');
  }
  return next();
}

ensureInitialData();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
// Configure the session middleware
// express-session handles creating a session ID and storing it in a cookie.
// The session data itself (like isAdmin, flash messages) is stored on the server (in memory by default).
app.use(
  session({
    // Secret used to sign the session ID cookie (encrypt/validate it).
    // In a real production app, this should be a long, random string from environment variables.
    secret: process.env.SESSION_SECRET || 'change_this_secret',

    // resave: false -> Do not save the session back to the store if it wasn't modified.
    // This improves performance and reduces race conditions.
    resave: false,

    // saveUninitialized: false -> Do not create a session until something is actually stored.
    // This is good for GDPR compliance (no cookie set until necessary) and saves storage.
    saveUninitialized: false
  })
);

/**
 * Global Middleware for View Variables (res.locals)
 * -------------------------------------------------
 * This middleware runs for EVERY request.
 * It sets variables in `res.locals`, making them directly available in ALL EJS templates.
 * This avoids having to pass these common variables (like `isAdmin`, `clubs`, `flash`) 
 * manually in every `res.render` call.
 */
app.use((req, res, next) => {
  // Make 'isAdmin' available in all views (true/false)
  res.locals.isAdmin = !!req.session.isAdmin;

  const dataForLocals = loadData();
  const clubs = dataForLocals.clubs || [];
  const dynamicCategories = clubs.map(c => c.name);
  const allCategories = Array.from(
    new Set([...DEFAULT_CATEGORIES, ...dynamicCategories])
  );
  const currentClubAdminClubId = req.session.clubAdminClubId || null;
  const currentClubAdminClub =
    clubs.find(c => c.id === currentClubAdminClubId) || null;

  // Make these variables available in all EJS templates
  res.locals.clubs = clubs;
  res.locals.categories = allCategories;
  res.locals.isClubAdmin = !!req.session.isClubAdmin;
  res.locals.currentClubAdminClub = currentClubAdminClub;

  // Handle flash messages (show once then delete)
  if (req.session.flash) {
    res.locals.flash = req.session.flash;
    delete req.session.flash;
  } else {
    res.locals.flash = null;
  }
  next();
});

/**
 * Public Route: Home Page
 * -----------------------
 * Displays the list of all activities.
 * Can be filtered by category (Robotique, IA, etc.) via query parameter ?category=...
 * It sorts activities: by date if available, otherwise by title.
 */
app.get('/', (req, res) => {
  const data = loadData();
  const selectedCategory = req.query.category || '';
  let activities = data.activities
    .slice()
    .sort((a, b) => {
      if (a.date && b.date) {
        return a.date.localeCompare(b.date);
      }
      return a.title.localeCompare(b.title);
    });

  if (selectedCategory) {
    activities = activities.filter(a => a.category === selectedCategory);
  }

  res.render('index', {
    pageTitle: 'Activites',
    activities,
    selectedCategory
  });
});

/**
 * Public Route: Activity Details
 * ------------------------------
 * Shows the full details of a specific activity.
 * Also lists the participants (students) who have already registered for it.
 * This page includes the registration form for new students.
 */
app.get('/activities/:id', (req, res) => {
  const data = loadData();
  const activity = data.activities.find(a => a.id === req.params.id);
  if (!activity) {
    return res.status(404).send('Activite non trouvee');
  }
  const participants = getParticipantsForActivity(data, activity.id);
  res.render('activity_detail', {
    pageTitle: activity.title,
    activity,
    participants,
    errors: [],
    formData: { firstName: '', lastName: '', email: '', filiere: '', ecole: '' }
  });
});

app.post('/activities/:id/register', (req, res) => {
  const { firstName, lastName, email, filiere, ecole } = req.body;
  const data = loadData();
  const activity = data.activities.find(a => a.id === req.params.id);
  if (!activity) {
    return res.status(404).send('Activite non trouvee');
  }
  const errors = [];
  if (!firstName || !firstName.trim()) errors.push('Le prenom est obligatoire.');
  if (!lastName || !lastName.trim()) errors.push('Le nom est obligatoire.');
  if (!email || !email.trim()) errors.push("L'email est obligatoire.");
  if (errors.length > 0) {
    const participants = getParticipantsForActivity(data, activity.id);
    return res.render('activity_detail', {
      pageTitle: activity.title,
      activity,
      participants,
      errors,
      formData: {
        firstName,
        lastName,
        email,
        filiere: filiere || '',
        ecole: ecole || ''
      }
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  let student = data.students.find(s => s.email.toLowerCase() === normalizedEmail);
  if (!student) {
    student = {
      id: uuidv4(),
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: normalizedEmail,
      classroom: '',
      filiere: filiere ? filiere.trim() : '',
      ecole: ecole ? ecole.trim() : ''
    };
    data.students.push(student);
  } else {
    student.firstName = firstName.trim();
    student.lastName = lastName.trim();
    if (filiere && filiere.trim()) {
      student.filiere = filiere.trim();
    }
    if (ecole && ecole.trim()) {
      student.ecole = ecole.trim();
    }
  }

  const existing = data.registrations.find(
    r => r.activityId === activity.id && r.studentId === student.id
  );
  if (!existing) {
    data.registrations.push({
      id: uuidv4(),
      activityId: activity.id,
      studentId: student.id,
      createdAt: new Date().toISOString()
    });
    saveData(data);
    req.session.flash = 'Inscription a cette activite enregistree.';
  } else {
    saveData(data);
    req.session.flash = 'Vous etes deja inscrit a cette activite.';
  }
  res.redirect('/activities/' + activity.id);
});

app.post('/clubs/join', (req, res) => {
  const { firstName, lastName, email, filiere, ecole, clubId } = req.body;
  const data = loadData();
  const club = (data.clubs || []).find(c => c.id === clubId);
  if (!club) {
    req.session.flash = 'Club introuvable.';
    return res.redirect('/');
  }

  const errors = [];
  if (!firstName || !firstName.trim()) errors.push('Le prenom est obligatoire.');
  if (!lastName || !lastName.trim()) errors.push('Le nom est obligatoire.');
  if (!email || !email.trim()) errors.push("L'email est obligatoire.");
  if (errors.length > 0) {
    req.session.flash = errors.join(' ');
    return res.redirect('/');
  }

  const normalizedEmail = email.trim().toLowerCase();
  let student = data.students.find(s => s.email.toLowerCase() === normalizedEmail);
  if (!student) {
    student = {
      id: uuidv4(),
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: normalizedEmail,
      classroom: '',
      filiere: filiere ? filiere.trim() : '',
      ecole: ecole ? ecole.trim() : ''
    };
    data.students.push(student);
  } else {
    student.firstName = firstName.trim();
    student.lastName = lastName.trim();
    if (filiere && filiere.trim()) {
      student.filiere = filiere.trim();
    }
    if (ecole && ecole.trim()) {
      student.ecole = ecole.trim();
    }
  }

  const memberships = data.clubMemberships || [];
  const existingMembership = memberships.find(
    m => m.clubId === club.id && m.studentId === student.id
  );

  if (!existingMembership) {
    memberships.push({
      id: uuidv4(),
      clubId: club.id,
      studentId: student.id,
      createdAt: new Date().toISOString()
    });
    data.clubMemberships = memberships;
    saveData(data);
    req.session.flash = 'Inscription au club enregistree.';
  } else {
    saveData(data);
    req.session.flash = 'Vous etes deja membre de ce club.';
  }

  res.redirect('/');
});

/**
 * Club Authentication Page (Public)
 * ---------------------------------
 * Displays the login/register forms for a student to access the "Club Space".
 * Note: This is DIFFERENT from the Club Admin login. 
 * This is for regular members to access their club's private area.
 */
app.get('/auth-club', (req, res) => {
  const data = loadData();
  const clubs = (data.clubs || [])
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name));

  res.render('auth_club', {
    pageTitle: 'Authentification du club',
    clubs,
    loginError: null,
    registerError: null
  });
});

app.post('/auth-club/login', (req, res) => {
  const { clubId, email, password } = req.body;
  const data = loadData();
  const clubs = (data.clubs || [])
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name));

  const errors = [];
  if (!clubId) errors.push('Le club est obligatoire.');
  if (!email || !email.trim()) errors.push("L'email est obligatoire.");
  if (!password) errors.push('Le mot de passe est obligatoire.');

  if (errors.length > 0) {
    return res.render('auth_club', {
      pageTitle: 'Authentification du club',
      clubs,
      loginError: errors.join(' '),
      registerError: null
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const students = data.students || [];
  const student = students.find(
    s => s.email && s.email.toLowerCase() === normalizedEmail
  );

  if (!student || !student.password || student.password !== password) {
    return res.render('auth_club', {
      pageTitle: 'Authentification du club',
      clubs,
      loginError: 'Identifiants incorrects.',
      registerError: null
    });
  }

  req.session.studentId = student.id;
  req.session.authClubId = clubId;
  req.session.flash = 'Connexion reussie.';
  res.redirect('/club-espace');
});

app.post('/auth-club/register', (req, res) => {
  const { clubId, firstName, lastName, email, filiere, password, confirmPassword } = req.body;
  const data = loadData();
  const clubs = (data.clubs || [])
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name));

  const errors = [];
  if (!clubId) errors.push('Le club est obligatoire.');
  if (!firstName || !firstName.trim()) errors.push('Le prenom est obligatoire.');
  if (!lastName || !lastName.trim()) errors.push('Le nom est obligatoire.');
  if (!email || !email.trim()) errors.push("L'email est obligatoire.");
  if (!password) errors.push('Le mot de passe est obligatoire.');
  if (password && password.length < 4) {
    errors.push('Le mot de passe doit contenir au moins 4 caracteres.');
  }
  if (password !== confirmPassword) {
    errors.push('Les mots de passe ne correspondent pas.');
  }

  if (errors.length > 0) {
    return res.render('auth_club', {
      pageTitle: 'Authentification du club',
      clubs,
      loginError: null,
      registerError: errors.join(' ')
    });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const students = data.students || [];
  let student = students.find(
    s => s.email && s.email.toLowerCase() === normalizedEmail
  );

  if (student && student.password) {
    return res.render('auth_club', {
      pageTitle: 'Authentification du club',
      clubs,
      loginError: null,
      registerError: 'Un compte existe deja avec cet email.'
    });
  }

  if (!student) {
    student = {
      id: uuidv4(),
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: normalizedEmail,
      classroom: '',
      filiere: filiere ? filiere.trim() : '',
      ecole: '',
      password: password
    };
    students.push(student);
    data.students = students;
  } else {
    student.firstName = firstName.trim();
    student.lastName = lastName.trim();
    if (filiere && filiere.trim()) {
      student.filiere = filiere.trim();
    }
    student.password = password;
  }

  const memberships = data.clubMemberships || [];
  const existingMembership = memberships.find(
    m => m.clubId === clubId && m.studentId === student.id
  );

  if (!existingMembership) {
    memberships.push({
      id: uuidv4(),
      clubId,
      studentId: student.id,
      createdAt: new Date().toISOString()
    });
    data.clubMemberships = memberships;
  }

  saveData(data);
  req.session.studentId = student.id;
  req.session.authClubId = clubId;
  req.session.flash = 'Compte cree et connexion reussie.';
  res.redirect('/club-espace');
});

/**
 * Club Space (Protected)
 * ----------------------
 * Accessible only after successful club login (via /auth-club).
 * Shows activities specific to that club and the list of members.
 * Checks `req.session.authClubId` to verify the user is logged in.
 */
app.get('/club-espace', (req, res) => {
  const data = loadData();
  const clubId = req.session.authClubId;

  if (!clubId) {
    req.session.flash = 'Veuillez vous connecter a un club.';
    return res.redirect('/auth-club');
  }

  const club = (data.clubs || []).find(c => c.id === clubId);

  if (!club) {
    req.session.authClubId = null;
    req.session.flash = 'Club introuvable.';
    return res.redirect('/auth-club');
  }

  const activities = data.activities
    .filter(a => a.category === club.name)
    .slice()
    .sort((a, b) => a.title.localeCompare(b.title));

  const membersItems = (data.clubMemberships || [])
    .filter(m => m.clubId === club.id)
    .map(m => {
      const student = data.students.find(s => s.id === m.studentId);
      return { membership: m, student };
    })
    .filter(x => x.student);

  res.render('club_space', {
    pageTitle: 'Espace du club',
    club,
    activities,
    membersItems
  });
});

/**
 * Admin Setup Route
 * -----------------
 * Special route used to create the FIRST admin account if none exist.
 * This prevents the system from being locked out if the data file is empty.
 */
app.get('/admin/setup', (req, res) => {
  const data = loadData();
  const admins = data.admins || [];
  res.render('admin/setup', {
    pageTitle: 'Creation du compte administrateur',
    error: null
  });
});

app.post('/admin/setup', (req, res) => {
  const {
    firstName,
    lastName,
    email,
    ecole,
    filiere,
    username,
    password,
    confirmPassword
  } = req.body;

  const trimmedFirstName = firstName ? firstName.trim() : '';
  const trimmedLastName = lastName ? lastName.trim() : '';
  const trimmedEmail = email ? email.trim() : '';
  const trimmedEcole = ecole ? ecole.trim() : '';
  const trimmedFiliere = filiere ? filiere.trim() : '';
  const trimmedUsername = username ? username.trim() : '';

  const data = loadData();
  const admins = data.admins || [];

  const errors = [];
  if (!trimmedFirstName) errors.push('Le prenom est obligatoire.');
  if (!trimmedLastName) errors.push('Le nom est obligatoire.');
  if (!trimmedEmail) errors.push("L'email est obligatoire.");
  if (!trimmedEcole) errors.push("L'ecole est obligatoire.");
  if (!trimmedFiliere) errors.push('La filiere est obligatoire.');
  if (!trimmedUsername) errors.push("L'identifiant est obligatoire.");
  if (!password) errors.push('Le mot de passe est obligatoire.');
  if (password && password.length < 4)
    errors.push('Le mot de passe doit contenir au moins 4 caracteres.');
  if (password !== confirmPassword)
    errors.push('Les mots de passe ne correspondent pas.');

  if (errors.length > 0) {
    return res.render('admin/setup', {
      pageTitle: 'Creation du compte administrateur',
      error: errors.join(' ')
    });
  }

  const newAdmin = {
    id: uuidv4(),
    firstName: trimmedFirstName,
    lastName: trimmedLastName,
    email: trimmedEmail,
    ecole: trimmedEcole,
    filiere: trimmedFiliere,
    username: trimmedUsername,
    password: password
  };

  data.admins = admins;
  data.admins.push(newAdmin);
  saveData(data);

  req.session.isAdmin = true;
  req.session.adminId = newAdmin.id;
  req.session.flash = 'Compte administrateur cree.';
  res.redirect('/admin');
});

/**
 * Admin Login Page (GET)
 * ----------------------
 * Displays the login form for the global administrator.
 * If the user is already logged in (req.session.isAdmin), redirects them to the dashboard immediately.
 * If no admins exist in the system, redirects to /admin/setup.
 */
app.get('/admin/login', (req, res) => {
  const data = loadData();
  const admins = data.admins || [];

  // If no admins exist, force setup
  if (admins.length === 0) {
    return res.redirect('/admin/setup');
  }

  if (req.session.isAdmin) {
    return res.redirect('/admin');
  }

  res.render('admin/login', { pageTitle: 'Connexion admin', error: null });
});

// Admin Login Logic (POST)
// Verifies credentials and sets session flags
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  const trimmedUsername = username ? username.trim() : '';

  const data = loadData();
  const admins = data.admins || [];
  const admin = admins.find(
    a => a.username === trimmedUsername && a.password === password
  );

  if (!admin) {
    return res.render('admin/login', {
      pageTitle: 'Connexion admin',
      error: 'Identifiants incorrects.'
    });
  }

  // Set session flags on successful login
  req.session.isAdmin = true;
  req.session.adminId = admin.id;
  const redirectTo = req.session.returnTo || '/admin';
  delete req.session.returnTo;
  req.session.flash = 'Connexion reussie.';
  res.redirect(redirectTo);
});

app.post('/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  req.session.adminId = null;
  req.session.flash = 'Vous etes deconnecte.';
  res.redirect('/');
});

/**
 * Admin Dashboard
 * ---------------
 * The main control panel for the global administrator.
 * Protected by `requireAdmin` middleware.
 * Gathers and displays overall statistics (counts of activities, students, etc.).
 */
app.get('/admin', requireAdmin, (req, res) => {
  const data = loadData();
  const stats = {
    activitiesCount: data.activities.length,
    studentsCount: data.students.length,
    registrationsCount: data.registrations.length,
    clubsCount: (data.clubs || []).length,
    clubMembershipsCount: (data.clubMemberships || []).length
  };
  res.render('admin/dashboard', {
    pageTitle: 'Tableau de bord',
    stats
  });
});

app.get('/admin/activities', requireAdmin, (req, res) => {
  const data = loadData();
  const activities = data.activities
    .slice()
    .sort((a, b) => a.title.localeCompare(b.title));
  res.render('admin/activities', {
    pageTitle: 'Activites',
    activities
  });
});

app.get('/admin/activities/new', requireAdmin, (req, res) => {
  res.render('admin/activity_form', {
    pageTitle: 'Nouvelle activite',
    activity: null,
    formAction: '/admin/activities'
  });
});

app.post('/admin/activities', requireAdmin, (req, res) => {
  const { title, description, date, category } = req.body;
  const data = loadData();
  const activity = {
    id: uuidv4(),
    title: title ? title.trim() : '',
    description: description ? description.trim() : '',
    date: date || '',
    category: category || ''
  };
  data.activities.push(activity);
  saveData(data);
  req.session.flash = 'Activite creee.';
  res.redirect('/admin/activities');
});

app.get('/admin/activities/:id/edit', requireAdmin, (req, res) => {
  const data = loadData();
  const activity = data.activities.find(a => a.id === req.params.id);
  if (!activity) {
    req.session.flash = 'Activite introuvable.';
    return res.redirect('/admin/activities');
  }
  res.render('admin/activity_form', {
    pageTitle: 'Modifier une activite',
    activity,
    formAction: '/admin/activities/' + activity.id
  });
});

app.post('/admin/activities/:id', requireAdmin, (req, res) => {
  const data = loadData();
  const activity = data.activities.find(a => a.id === req.params.id);
  if (!activity) {
    req.session.flash = 'Activite introuvable.';
    return res.redirect('/admin/activities');
  }
  const { title, description, date, category } = req.body;
  activity.title = title ? title.trim() : '';
  activity.description = description ? description.trim() : '';
  activity.date = date || '';
  activity.category = category || '';
  saveData(data);
  req.session.flash = 'Activite mise a jour.';
  res.redirect('/admin/activities');
});

app.post('/admin/activities/:id/delete', requireAdmin, (req, res) => {
  const data = loadData();
  const id = req.params.id;
  const beforeCount = data.activities.length;
  data.activities = data.activities.filter(a => a.id !== id);
  data.registrations = data.registrations.filter(r => r.activityId !== id);
  saveData(data);
  if (data.activities.length < beforeCount) {
    req.session.flash = 'Activite supprimee.';
  } else {
    req.session.flash = 'Activite introuvable.';
  }
  res.redirect('/admin/activities');
});

/**
 * Admin: Student Management
 * -------------------------
 * Lists all registered students.
 * Also shows which clubs they belong to by cross-referencing `clubMemberships`.
 */
app.get('/admin/students', requireAdmin, (req, res) => {
  const data = loadData();
  const memberships = data.clubMemberships || [];
  const clubs = data.clubs || [];

  const students = data.students
    .slice()
    .sort((a, b) => a.lastName.localeCompare(b.lastName))
    .map(student => {
      const studentMemberships = memberships.filter(
        m => m.studentId === student.id
      );
      const clubNames = studentMemberships
        .map(m => {
          const club = clubs.find(c => c.id === m.clubId);
          return club ? club.name : null;
        })
        .filter(Boolean);

      return {
        ...student,
        filiere: student.filiere || '',
        ecole: student.ecole || student.universite || '',
        clubsLabel: clubNames.join(', ')
      };
    });
  res.render('admin/students', {
    pageTitle: 'Etudiants',
    students
  });
});

app.post('/admin/students', requireAdmin, (req, res) => {
  const { firstName, lastName, email, classroom, filiere, ecole, clubId } = req.body;
  if (!email || !email.trim()) {
    req.session.flash = 'Email obligatoire pour creer un etudiant.';
    return res.redirect('/admin/students');
  }
  const data = loadData();
  const normalizedEmail = email.trim().toLowerCase();
  let student = data.students.find(s => s.email.toLowerCase() === normalizedEmail);
  if (student) {
    req.session.flash = 'Un etudiant avec cet email existe deja.';
    return res.redirect('/admin/students');
  }
  student = {
    id: uuidv4(),
    firstName: firstName ? firstName.trim() : '',
    lastName: lastName ? lastName.trim() : '',
    email: normalizedEmail,
    classroom: classroom ? classroom.trim() : '',
    filiere: filiere ? filiere.trim() : '',
    ecole: ecole ? ecole.trim() : ''
  };
  data.students.push(student);

  // Si un club est sélectionné, ajouter l'étudiant comme membre de ce club
  if (clubId) {
    const club = (data.clubs || []).find(c => c.id === clubId);
    if (club) {
      const memberships = data.clubMemberships || [];
      const exists = memberships.find(
        m => m.clubId === clubId && m.studentId === student.id
      );
      if (!exists) {
        memberships.push({
          id: uuidv4(),
          clubId,
          studentId: student.id,
          createdAt: new Date().toISOString()
        });
        data.clubMemberships = memberships;
      }
    }
  }
  saveData(data);
  req.session.flash = 'Etudiant ajoute.';
  res.redirect('/admin/students');
});

app.post('/admin/students/:id/delete', requireAdmin, (req, res) => {
  const data = loadData();
  const id = req.params.id;
  const beforeCount = data.students.length;
  data.students = data.students.filter(s => s.id !== id);
  data.registrations = data.registrations.filter(r => r.studentId !== id);
  if (data.clubMemberships) {
    data.clubMemberships = data.clubMemberships.filter(m => m.studentId !== id);
  }
  saveData(data);
  if (data.students.length < beforeCount) {
    req.session.flash = 'Etudiant supprime.';
  } else {
    req.session.flash = 'Etudiant introuvable.';
  }
  res.redirect('/admin/students');
});

app.get('/admin/registrations', requireAdmin, (req, res) => {
  const data = loadData();
  const items = data.registrations
    .map(r => {
      const activity = data.activities.find(a => a.id === r.activityId);
      const student = data.students.find(s => s.id === r.studentId);
      return { registration: r, activity, student };
    })
    .filter(x => x.activity && x.student);
  res.render('admin/registrations', {
    pageTitle: 'Inscriptions activites',
    items
  });
});

/**
 * Admin: Club Management
 * ----------------------
 * Lists all clubs in the system.
 * Calculates dynamic stats for each club (number of members, number of activities).
 */
app.get('/admin/clubs', requireAdmin, (req, res) => {
  const data = loadData();
  const clubs = (data.clubs || []).map(club => {
    const membersCount = (data.clubMemberships || []).filter(
      m => m.clubId === club.id
    ).length;
    const activitiesCount = data.activities.filter(
      a => a.category === club.name
    ).length;
    return {
      id: club.id,
      name: club.name,
      membersCount,
      activitiesCount
    };
  });

  res.render('admin/clubs', {
    pageTitle: 'Clubs',
    clubs
  });
});

app.post('/admin/clubs', requireAdmin, (req, res) => {
  const { name } = req.body;
  const trimmed = name ? name.trim() : '';
  if (!trimmed) {
    req.session.flash = 'Le nom du club est obligatoire.';
    return res.redirect('/admin/clubs');
  }

  const data = loadData();
  const exists = (data.clubs || []).some(
    c => c.name.toLowerCase() === trimmed.toLowerCase()
  );
  if (exists) {
    req.session.flash = 'Un club avec ce nom existe deja.';
    return res.redirect('/admin/clubs');
  }

  if (!data.clubs) data.clubs = [];
  data.clubs.push({ id: uuidv4(), name: trimmed });
  saveData(data);
  req.session.flash = 'Club ajoute.';
  res.redirect('/admin/clubs');
});

app.post('/admin/clubs/:id/delete', requireAdmin, (req, res) => {
  const data = loadData();
  const id = req.params.id;
  const beforeCount = (data.clubs || []).length;
  data.clubs = (data.clubs || []).filter(c => c.id !== id);
  if (data.clubMemberships) {
    data.clubMemberships = data.clubMemberships.filter(m => m.clubId !== id);
  }
  saveData(data);

  if (data.clubs.length < beforeCount) {
    req.session.flash = 'Club supprime.';
  } else {
    req.session.flash = 'Club introuvable.';
  }
  res.redirect('/admin/clubs');
});

app.get('/admin/clubs/:id/admin', requireAdmin, (req, res) => {
  const data = loadData();
  const clubId = req.params.id;
  const club = (data.clubs || []).find(c => c.id === clubId);

  if (!club) {
    req.session.flash = 'Club introuvable.';
    return res.redirect('/admin/clubs');
  }

  const clubAdmins = data.clubAdmins || [];
  const clubAdmin = clubAdmins.find(a => a.clubId === club.id) || null;

  res.render('admin/club_admin_form', {
    pageTitle: 'Admin du club',
    club,
    clubAdmin,
    error: null
  });
});

app.post('/admin/clubs/:id/admin', requireAdmin, (req, res) => {
  const clubId = req.params.id;
  const { username, password, confirmPassword } = req.body;
  const trimmedUsername = username ? username.trim() : '';

  const errors = [];
  if (!trimmedUsername) errors.push("L'identifiant est obligatoire.");
  if (!password) errors.push('Le mot de passe est obligatoire.');
  if (password && password.length < 4) {
    errors.push('Le mot de passe doit contenir au moins 4 caracteres.');
  }
  if (password !== confirmPassword) {
    errors.push('Les mots de passe ne correspondent pas.');
  }

  const data = loadData();
  const club = (data.clubs || []).find(c => c.id === clubId);
  if (!club) {
    req.session.flash = 'Club introuvable.';
    return res.redirect('/admin/clubs');
  }

  if (errors.length > 0) {
    const clubAdmins = data.clubAdmins || [];
    const clubAdmin = clubAdmins.find(a => a.clubId === club.id) || null;
    return res.render('admin/club_admin_form', {
      pageTitle: 'Admin du club',
      club,
      clubAdmin,
      error: errors.join(' ')
    });
  }

  if (!data.clubAdmins) data.clubAdmins = [];
  let clubAdmin = data.clubAdmins.find(a => a.clubId === club.id);

  if (!clubAdmin) {
    clubAdmin = {
      id: uuidv4(),
      clubId: club.id,
      username: trimmedUsername,
      password: password
    };
    data.clubAdmins.push(clubAdmin);
  } else {
    clubAdmin.username = trimmedUsername;
    clubAdmin.password = password;
  }

  saveData(data);
  req.session.flash = 'Compte administrateur du club enregistre.';
  res.redirect('/admin/clubs');
});

app.get('/admin/club-memberships', requireAdmin, (req, res) => {
  const data = loadData();
  const items = (data.clubMemberships || [])
    .map(m => {
      const club = (data.clubs || []).find(c => c.id === m.clubId);
      const student = data.students.find(s => s.id === m.studentId);
      return { membership: m, club, student };
    })
    .filter(x => x.club && x.student);

  const clubs = (data.clubs || []).slice().sort((a, b) =>
    a.name.localeCompare(b.name)
  );
  const students = data.students
    .slice()
    .sort((a, b) => a.lastName.localeCompare(b.lastName));

  res.render('admin/club_memberships', {
    pageTitle: 'Membres des clubs',
    items,
    clubs,
    students
  });
});

app.post('/admin/club-memberships', requireAdmin, (req, res) => {
  const { clubId, studentId } = req.body;
  const data = loadData();

  const club = (data.clubs || []).find(c => c.id === clubId);
  const student = data.students.find(s => s.id === studentId);

  if (!club || !student) {
    req.session.flash = 'Club ou etudiant introuvable.';
    return res.redirect('/admin/club-memberships');
  }

  const memberships = data.clubMemberships || [];
  const existing = memberships.find(
    m => m.clubId === clubId && m.studentId === studentId
  );

  if (existing) {
    req.session.flash = 'Cet etudiant est deja membre de ce club.';
    return res.redirect('/admin/club-memberships');
  }

  memberships.push({
    id: uuidv4(),
    clubId,
    studentId,
    createdAt: new Date().toISOString()
  });
  data.clubMemberships = memberships;
  saveData(data);

  req.session.flash = 'Membre ajoute au club.';
  res.redirect('/admin/club-memberships');
});

app.post('/admin/club-memberships/:id/delete', requireAdmin, (req, res) => {
  const membershipId = req.params.id;
  const data = loadData();
  const beforeCount = (data.clubMemberships || []).length;
  data.clubMemberships = (data.clubMemberships || []).filter(
    m => m.id !== membershipId
  );
  saveData(data);

  if ((data.clubMemberships || []).length < beforeCount) {
    req.session.flash = 'Membre retire du club.';
  } else {
    req.session.flash = 'Membre introuvable.';
  }

  res.redirect('/admin/club-memberships');
});

/**
 * Club Admin Login
 * ----------------
 * Login page specifically for a Club Administrator.
 * Each club can have one or more assigned admins.
 * This route is accessed typically via /clubs/:id/admin/login.
 */
app.get('/clubs/:id/admin/login', (req, res) => {
  const data = loadData();
  const clubId = req.params.id;
  const club = (data.clubs || []).find(c => c.id === clubId);

  if (!club) {
    return res.status(404).send('Club introuvable');
  }

  const clubAdmins = data.clubAdmins || [];
  const clubAdmin = clubAdmins.find(a => a.clubId === club.id);

  if (!clubAdmin) {
    return res
      .status(403)
      .send(
        "Aucun compte administrateur n'est defini pour ce club. Veuillez contacter l'administrateur principal."
      );
  }

  if (req.session.isClubAdmin && req.session.clubAdminClubId === club.id) {
    return res.redirect('/club-admin');
  }

  res.render('club_admin/login', {
    pageTitle: 'Connexion admin club',
    club,
    error: null
  });
});

app.post('/clubs/:id/admin/login', (req, res) => {
  const { username, password } = req.body;
  const trimmedUsername = username ? username.trim() : '';

  const data = loadData();
  const clubId = req.params.id;
  const club = (data.clubs || []).find(c => c.id === clubId);

  if (!club) {
    return res.status(404).send('Club introuvable');
  }

  const clubAdmins = data.clubAdmins || [];
  const admin = clubAdmins.find(
    a =>
      a.clubId === club.id &&
      a.username === trimmedUsername &&
      a.password === password
  );

  if (!admin) {
    return res.render('club_admin/login', {
      pageTitle: 'Connexion admin club',
      club,
      error: 'Identifiants incorrects pour ce club.'
    });
  }

  req.session.isClubAdmin = true;
  req.session.clubAdminId = admin.id;
  req.session.clubAdminClubId = club.id;

  res.redirect('/club-admin');
});

/**
 * Club Admin Dashboard
 * --------------------
 * The dedicated dashboard for a logged-in Club Admin.
 * Protected by `requireClubAdmin` middleware.
 * Shows ONLY the activities and members related to THEIR club.
 */
app.get('/club-admin', requireClubAdmin, (req, res) => {
  const data = loadData();
  const clubId = req.session.clubAdminClubId;
  const club = (data.clubs || []).find(c => c.id === clubId);

  if (!club) {
    req.session.isClubAdmin = false;
    req.session.clubAdminId = null;
    req.session.clubAdminClubId = null;
    return res.status(404).send('Club introuvable');
  }

  const activities = data.activities
    .filter(a => a.category === club.name)
    .slice()
    .sort((a, b) => a.title.localeCompare(b.title));

  const membersItems = (data.clubMemberships || [])
    .filter(m => m.clubId === club.id)
    .map(m => {
      const student = data.students.find(s => s.id === m.studentId);
      return { membership: m, student };
    })
    .filter(x => x.student);

  const stats = {
    activitiesCount: activities.length,
    membersCount: membersItems.length
  };

  res.render('club_admin/dashboard', {
    pageTitle: 'Espace admin du club',
    club,
    activities,
    membersItems,
    stats
  });
});

app.post('/club-admin/logout', (req, res) => {
  req.session.isClubAdmin = false;
  req.session.clubAdminId = null;
  req.session.clubAdminClubId = null;
  req.session.flash = 'Vous etes deconnecte en tant que responsable de club.';
  res.redirect('/');
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('Serveur demarre sur http://localhost:' + PORT);
});
