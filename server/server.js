// server/server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const multer = require('multer');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Инициализация БД
const db = new sqlite3.Database('./users.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    fullName TEXT,
    bio TEXT,
    avatar TEXT
  )`);
});

// Multer для загрузки аватара
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Регистрация
app.post('/api/register', async (req, res) => {
  const { email, password, fullName } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (email, password, fullName, bio, avatar) VALUES (?, ?, ?, '', '')`,
      [email, hashedPassword, fullName],
      function (err) {
        if (err) return res.status(400).json({ error: 'Email уже используется' });
        res.status(201).json({ id: this.lastID, email, fullName });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Авторизация
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Неверный email или пароль' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Неверный email или пароль' });

    const token = jwt.sign({ id: user.id }, 'secret-key', { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, email: user.email, fullName: user.fullName, avatar: user.avatar } });
  });
});

// Получение профиля
app.get('/api/profile', verifyToken, (req, res) => {
  db.get('SELECT id, email, fullName, bio, avatar FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json(user);
  });
});

// Обновление профиля
// server/server.js — обновлённый PUT /api/profile
app.put('/api/profile', verifyToken, upload.single('avatar'), (req, res) => {
  const { fullName, bio } = req.body;
  let avatar = req.body.avatar || ''; // если не передан — оставляем старое

  // Если загружен файл — используем его путь
  if (req.file) {
    avatar = '/uploads/' + req.file.filename;
  }

  db.run(
    `UPDATE users SET fullName = ?, bio = ?, avatar = ? WHERE id = ?`,
    [fullName, bio, avatar, req.user.id],
    function (err) {
      if (err) {
        console.error('Ошибка БД:', err);
        return res.status(400).json({ error: 'Ошибка обновления профиля' });
      }
      // Возвращаем обновлённые данные
      db.get('SELECT id, email, fullName, bio, avatar FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Не удалось получить профиль' });
        res.json(user);
      });
    }
  );
});

// Middleware для проверки токена
function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
  jwt.verify(token, 'secret-key', (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Неверный токен' });
    req.user = decoded;
    next();
  });
}

// Создаём папку uploads, если её нет
if (!require('fs').existsSync('uploads')) {
  require('fs').mkdirSync('uploads');
}

app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));