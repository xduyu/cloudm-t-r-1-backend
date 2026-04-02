import express from 'express';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import multer from 'multer';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const USERS_FILE = path.join(__dirname, 'user.json');
const TRACKS_FILE = path.join(__dirname, 'tracks.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads/tracks');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const app = express();
const PORT = process.env.PORT || 4000;
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'secret-key';

app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const COVERS_DIR = path.join(__dirname, 'uploads/covers');
if (!fs.existsSync(COVERS_DIR)) fs.mkdirSync(COVERS_DIR, { recursive: true });

const coverStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'cover') cb(null, COVERS_DIR);
    else cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  },
});

const uploadFields = multer({
  storage: coverStorage,
  fileFilter: (req, file, cb) => {
    const allowed = ['.mp3', '.wav', '.flac', '.ogg', '.m4a', '.jpg', '.jpeg', '.png', '.webp', '.gif'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Недопустимый формат файла'));
  },
  limits: { fileSize: 50 * 1024 * 1024 },
}).fields([
  { name: 'file', maxCount: 1 },
  { name: 'cover', maxCount: 1 },
]);

function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return []; }
}

function saveUserData(newUser) {
  try {
    const users = readUsers();
    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) { console.error('Ошибка записи:', err); }
}

function readTracks() {
  if (!fs.existsSync(TRACKS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(TRACKS_FILE, 'utf8')); }
  catch { return []; }
}

function saveTrackData(newTrack) {
  try {
    const tracks = readTracks();
    tracks.push(newTrack);
    fs.writeFileSync(TRACKS_FILE, JSON.stringify(tracks, null, 2), 'utf8');
  } catch (err) { console.error('Ошибка записи:', err); }
}


function requireAdmin(req, res, next) {
  const users = readUsers();
  const user = users.find(u => u.username === req.user.user.username);
  if (!user) return res.status(404).json({ message: 'User not found' });
  if (!user.isAdmin) return res.status(403).json({ message: 'Forbidden' });
  req.dbUser = user;
  next();
}
 
function requireMod(req, res, next) {
  const users = readUsers();
  const user = users.find(u => u.username === req.user.user.username);
  if (!user) return res.status(404).json({ message: 'User not found' });
  if (!user.isAdmin && !user.isMod) return res.status(403).json({ message: 'Forbidden' });
  req.dbUser = user;
  next();
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get('/', (req, res) => res.json({ message: 'API is running' }));

app.post('/api/auth/register', (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email)
    return res.status(400).json({ message: 'All fields required' });

  const users = readUsers();
  if (users.find(u => u.username === username))
    return res.status(400).json({ message: 'Username already exists' });

  const user = {
    profilePicture: null, username, password, email,
    isArtist: false, subscribedArtists: [], FavouriteTracks: [],
    Alboums: [], Playlists: [], SubScribtionType: 'free',
    isAdmin: false, isMod: false,
  };

  saveUserData(user);
  const { password: _, ...safeUser } = user;
  res.status(201).json({ message: 'Пользователь зарегистрирован', user: safeUser });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'All fields required' });

  const users = readUsers();
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ message: 'Invalid username or password' });

  const { password: _, ...payload } = user;
  const token = jwt.sign({ user: payload }, TOKEN_SECRET, { expiresIn: '31d' });
  res.json({ message: 'Login successful', token, user: payload });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  try {
    const users = readUsers();
    const user = users.find(
      u => u.username === req.user.user.username
    );
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const { password, ...safeUser } = user;
    res.json({
      user: safeUser
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


app.post('/api/tracks', authenticateToken, uploadFields, (req, res) => {
  const { title, artist, album, duration } = req.body;
  if (!title || !artist || !album)
    return res.status(400).json({ message: 'title, artist, album обязательны' });

  const audioFile = req.files?.['file']?.[0];
  const coverFile = req.files?.['cover']?.[0];

  if (!audioFile)
    return res.status(400).json({ message: 'Аудио файл обязателен' });

  const track = {
    id: Date.now().toString(),
    title, artist, album,
    duration: duration || null,
    addedBy: req.user.user.username,
    plays: 0,
    filename: audioFile.filename,
    url: `http://localhost:${PORT}/uploads/tracks/${audioFile.filename}`,
    coverFilename: coverFile?.filename || null,
    coverUrl: coverFile
      ? `http://localhost:${PORT}/uploads/covers/${coverFile.filename}`
      : null,
  };

  saveTrackData(track);
  res.status(201).json({ message: 'Трек сохранён', track });
});

app.post('/api/tracks/add-favorite/:id', authenticateToken, (req, res) => {
  const trackId = req.params.id;

  const tracks = readTracks();
  const track = tracks.find(t => t.id === trackId);
  if (!track) return res.status(404).json({ message: 'Track not found' });

  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === req.user.user.username);
  if (userIndex === -1) return res.status(404).json({ message: 'User not found' });
  if (!users[userIndex].FavouriteTracks) {
    users[userIndex].FavouriteTracks = [];
  }
  const favourites = users[userIndex].FavouriteTracks;
  const isLiked = favourites.includes(trackId);

  if (isLiked) {
    users[userIndex].FavouriteTracks = favourites.filter(id => id !== trackId);

    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');

    return res.json({ message: 'Removed from favorites', liked: false });
  } else {
    favourites.push(trackId);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    return res.json({ message: 'Added to favorites', liked: true });
  }
});

app.get('/api/artists/:name', (req, res) => {
  const name = req.params.name.toLowerCase();
  const users = readUsers();
  const artist = users.find(u => u.isArtist && u.username.toLowerCase() === name);
  if (!artist) return res.status(404).json({ message: 'Artist not found' });

  const { password, ...safeArtist } = artist;
  res.json({ artist: safeArtist });
});

app.get('/api/artists/:name/tracks', (req, res) => {
  const name = req.params.name.toLowerCase();
  const users = readUsers();
  const artist = users.find(u => u.isArtist && u.username.toLowerCase() === name);
  if (!artist) return res.status(404).json({ message: 'Artist not found' });

  const tracks = readTracks().filter(t => t.addedBy === artist.username);
  res.json({ tracks });
});

app.get('/api/tracks', authenticateToken, (req, res) => {
  const tracks = readTracks();
  const users = readUsers();
  const user = users.find(u => u.username === req.user.user.username); // свежие данные

  if (!user) return res.status(404).json({ message: 'User not found' });

  if (user.isAdmin || user.isMod) return res.json({ tracks });
  if (user.isArtist) return res.json({ tracks: tracks.filter(t => t.addedBy === user.username) });

  res.json({ tracks });
});

app.delete('/api/tracks/:id', authenticateToken, (req, res) => {
  const { user } = req.user;
  const tracks = readTracks();
  const trackIndex = tracks.findIndex(t => t.id === req.params.id);

  if (trackIndex === -1) return res.status(404).json({ message: 'Track not found' });

  const track = tracks[trackIndex];
  if (!user.isAdmin && !user.isMod && track.addedBy !== user.username)
    return res.status(403).json({ message: 'Forbidden' });

  const filePath = path.join(UPLOADS_DIR, track.filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  tracks.splice(trackIndex, 1);
  fs.writeFileSync(TRACKS_FILE, JSON.stringify(tracks, null, 2), 'utf8');
  res.json({ message: 'Track deleted' });
});

app.put('/api/tracks/:id', authenticateToken, uploadFields, (req, res) => {
  const { user } = req.user;
  const tracks = readTracks();
  const trackIndex = tracks.findIndex(t => t.id === req.params.id);
  if (trackIndex === -1) return res.status(404).json({ message: 'Track not found' });

  const track = tracks[trackIndex];
  if (!user.isAdmin && !user.isMod && track.addedBy !== user.username)
    return res.status(403).json({ message: 'Forbidden' });

  const { title, artist, album, duration } = req.body;
  const coverFile = req.files?.['cover']?.[0];

  if (coverFile && track.coverFilename) {
    const oldPath = path.join(COVERS_DIR, track.coverFilename);
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
  }

  tracks[trackIndex] = {
    ...track, title, artist, album, duration,
    ...(coverFile && {
      coverFilename: coverFile.filename,
      coverUrl: `http://localhost:${PORT}/uploads/covers/${coverFile.filename}`,
    }),
  };

  fs.writeFileSync(TRACKS_FILE, JSON.stringify(tracks, null, 2), 'utf8');
  res.json({ message: 'Track updated', track: tracks[trackIndex] });
});

app.get('/api/admin/users', authenticateToken, requireMod, (req, res) => {
  const users = readUsers().map(({ password, ...u }) => u);
  res.json({ users });
});

app.get('/api/admin/users/:username', authenticateToken, requireMod, (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.username === req.params.username);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const { password, ...safeUser } = user;
  res.json({ user: safeUser });
});

app.patch('/api/admin/users/:username', authenticateToken, requireAdmin, (req, res) => {
  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === req.params.username);
  if (userIndex === -1) return res.status(404).json({ message: 'User not found' });

  const allowed = ['isArtist', 'isAdmin', 'isMod', 'SubScribtionType', 'profilePicture'];
  const updates = {};
  for (const key of allowed) {
    if (key in req.body) updates[key] = req.body[key];
  }
 
  users[userIndex] = { ...users[userIndex], ...updates };
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
 
  const { password, ...safeUser } = users[userIndex];
  res.json({ message: 'User updated', user: safeUser });
});

app.delete('/api/admin/users/:username', authenticateToken, requireAdmin, (req, res) => {
  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === req.params.username);
  if (userIndex === -1) return res.status(404).json({ message: 'User not found' });

  if (users[userIndex].username === req.dbUser.username)
    return res.status(400).json({ message: 'Cannot delete yourself' });
 
  users.splice(userIndex, 1);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  res.json({ message: 'User deleted' });
});
 
app.get('/api/admin/tracks', authenticateToken, requireMod, (req, res) => {
  const tracks = readTracks();
  res.json({ tracks });
});

app.delete('/api/admin/tracks/:id', authenticateToken, requireMod, (req, res) => {
  const tracks = readTracks();
  const trackIndex = tracks.findIndex(t => t.id === req.params.id);
  if (trackIndex === -1) return res.status(404).json({ message: 'Track not found' });
 
  const track = tracks[trackIndex];
  const filePath = path.join(UPLOADS_DIR, track.filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
 
  tracks.splice(trackIndex, 1);
  fs.writeFileSync(TRACKS_FILE, JSON.stringify(tracks, null, 2), 'utf8');
  res.json({ message: 'Track deleted' });
});

app.put('/api/admin/tracks/:id', authenticateToken, requireMod, (req, res) => {
  const tracks = readTracks();
  const trackIndex = tracks.findIndex(t => t.id === req.params.id);
  if (trackIndex === -1) return res.status(404).json({ message: 'Track not found' });
 
  const { title, artist, album, duration } = req.body;
  tracks[trackIndex] = { ...tracks[trackIndex], title, artist, album, duration };
  fs.writeFileSync(TRACKS_FILE, JSON.stringify(tracks, null, 2), 'utf8');
  res.json({ message: 'Track updated', track: tracks[trackIndex] });
});

app.get('/api/admin/stats', authenticateToken, requireMod, (req, res) => {
  const users = readUsers();
  const tracks = readTracks();
 
  res.json({
    totalUsers: users.length,
    totalTracks: tracks.length,
    totalArtists: users.filter(u => u.isArtist).length,
    totalAdmins: users.filter(u => u.isAdmin).length,
    totalMods: users.filter(u => u.isMod).length,
    subscriptions: {
      free: users.filter(u => u.SubScribtionType === 'free').length,
      premium: users.filter(u => u.SubScribtionType === 'premium').length,
      platinum: users.filter(u => u.SubScribtionType === 'platinum').length,
    },
    totalPlays: tracks.reduce((sum, t) => sum + (t.plays || 0), 0),
  });
});

app.patch('/api/admin/ban', authenticateToken, requireMod, (req, res) => {
  const { username, banned } = req.body;

  if (!username) return res.status(400).json({ message: 'Username is required' });

  const users = readUsers();
  const userIndex = users.findIndex(u => u.username === username);
  if (userIndex === -1) return res.status(404).json({ message: 'User not found' });

  if (users[userIndex].username === req.dbUser.username)
    return res.status(400).json({ message: 'Cannot ban yourself' });

  if (users[userIndex].isAdmin && !req.dbUser.isAdmin)
    return res.status(403).json({ message: 'Mods cannot ban admins' });

  users[userIndex].isBanned = banned ?? !users[userIndex].isBanned;
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');

  const { password, ...safeUser } = users[userIndex];
  res.json({
    message: users[userIndex].isBanned ? 'User banned' : 'User unbanned',
    user: safeUser,
  });
});
 
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));