const express = require('express');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { OpenAI } = require('openai');

const app = express();
const PORT = 3000;

// 🔑 Твой API ключ Gemini
const GEMINI_API_KEY = 'AIzaSyAsYC3BWIJpjIzrzrtDTXM9BecTfTND2YY';
const OPENAI_API_KEY = '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';

const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 дней
}));

let chatSession = null;

// Настройка подключения к PostgreSQL
const pool = new Pool({
  user: 'myuser', // ваш пользователь
  host: 'localhost',
  database: 'aichat', // ваша база
  password: 'mypassword', // ваш пароль
  port: 5432,
});

// Создать таблицу, если не существует
pool.query(`CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  sender VARCHAR(10) NOT NULL,
  text TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`);

// Новый маршрут для чата на OpenAI GPT (теперь с новым синтаксисом)
app.post('/api/chat2', async (req, res) => {
  const userMessage = req.body.message;
  const userIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  try {
    let user;
    if (req.session.user) {
      // Зарегистрированный пользователь — увеличиваем requests по email
      await pool.query('UPDATE users SET requests = requests + 1 WHERE email = $1', [req.session.user.email]);
      const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [req.session.user.email]);
      user = userRes.rows[0];
    } else {
      // Гость — ищем по ip
      const userRes = await pool.query('SELECT * FROM users WHERE ip = $1', [userIp]);
      if (userRes.rows.length === 0) {
        // Новый гость
        await pool.query('INSERT INTO users(ip, requests) VALUES($1, 1)', [userIp]);
        user = { ip: userIp, requests: 1 };
      } else {
        user = userRes.rows[0];
        // Проверяем лимит для гостей (нет name/email)
        if (!user.name && !user.email && user.requests >= 4) {
          return res.json({ limitExceeded: true });
        }
        // Гость — увеличиваем requests
        await pool.query('UPDATE users SET requests = requests + 1 WHERE ip = $1', [userIp]);
        user.requests += 1;
      }
    }

    // Сохраняем сообщение пользователя
    console.log('Сохраняем сообщение пользователя (GPT):', userMessage);
    await pool.query('INSERT INTO messages(sender, text) VALUES($1, $2)', ['user', userMessage]);

    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: 'Ты — доброжелательный ассистент. Отвечай кратко, вежливо и на русском языке.' },
        { role: 'user', content: userMessage }
      ]
    });
    const gptReply = completion.choices[0].message.content;
    console.log('Сохраняем ответ бота (GPT):', gptReply);
    // Сохраняем ответ бота
    await pool.query('INSERT INTO messages(sender, text) VALUES($1, $2)', ['bot', gptReply]);
    res.json({ reply: gptReply, requests: user.requests ? user.requests + 1 : 1 });
  } catch (error) {
    console.error('OpenAI API Error:', error);
    res.status(500).json({ error: 'Ошибка при обращении к OpenAI API' });
  }
});



// Маршрут для чата
app.post('/api/chat', async (req, res) => {
  const userMessage = req.body.message;
  const userIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  try {
    let user;
    if (req.session.user) {
      // Зарегистрированный пользователь — увеличиваем requests по email
      await pool.query('UPDATE users SET requests = requests + 1 WHERE email = $1', [req.session.user.email]);
      const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [req.session.user.email]);
      user = userRes.rows[0];
    } else {
      // Гость — ищем по ip
      const userRes = await pool.query('SELECT * FROM users WHERE ip = $1', [userIp]);
      if (userRes.rows.length === 0) {
        // Новый гость
        await pool.query('INSERT INTO users(ip, requests) VALUES($1, 1)', [userIp]);
        user = { ip: userIp, requests: 1 };
      } else {
        user = userRes.rows[0];
        // Проверяем лимит для гостей (нет name/email)
        if (!user.name && !user.email && user.requests >= 4) {
          return res.json({ limitExceeded: true });
        }
        // Гость — увеличиваем requests
        await pool.query('UPDATE users SET requests = requests + 1 WHERE ip = $1', [userIp]);
        user.requests += 1;
      }
    }

    if (!chatSession) {
      const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

      chatSession = model.startChat({
        history: [
          {
            role: 'user',
            parts: [
              { text: 'Ты — доброжелательный ассистент. Отвечай кратко, вежливо и на русском языке. Когда тебя спрашивают кто ты, то отвечай что ты русский чат бот - ГОЙДАГПТ' }
            ]
          }
        ],
        generationConfig: {
          temperature: 0.7,
          topK: 32,
          topP: 1,
          maxOutputTokens: 1024,
        }
      });
    }

    console.log('Сохраняем сообщение пользователя:', userMessage);
    await pool.query('INSERT INTO messages(sender, text) VALUES($1, $2)', ['user', userMessage]);

    const result = await chatSession.sendMessage(userMessage);
    const text = result.response.text();
    console.log('Сохраняем ответ бота:', text);
    // Сохраняем ответ бота
    await pool.query('INSERT INTO messages(sender, text) VALUES($1, $2)', ['bot', text]);
    res.json({ reply: text, requests: user.requests ? user.requests + 1 : 1 });
  } catch (error) {
    console.error('Gemini API Error:', error);
    res.status(500).json({ error: 'Ошибка при обращении к Gemini API' });
  }
});

// Регистрация пользователя с хешированием пароля
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const userIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    // Проверяем, есть ли уже гость с этим ip
    const userRes = await pool.query('SELECT * FROM users WHERE ip = $1', [userIp]);
    if (userRes.rows.length > 0 && !userRes.rows[0].email) {
      // Гость — обновляем запись, добавляем данные
      await pool.query(
        'UPDATE users SET name=$1, email=$2, password=$3 WHERE ip=$4',
        [name, email, hash, userIp]
      );
      return res.json({ success: true });
    }
    // Если email уже есть — ошибка
    const emailRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (emailRes.rows.length > 0) {
      return res.status(409).json({ error: 'Пользователь с таким email уже существует' });
    }
    // Новый пользователь
    await pool.query(
      'INSERT INTO users(name, email, password, ip, requests) VALUES($1, $2, $3, $4, 1)',
      [name, email, hash, userIp]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('DB Registration Error:', error);
    res.status(500).json({ error: 'Ошибка регистрации' });
  }
});

// Вход пользователя с bcrypt и сессией
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Все поля обязательны' });
  }
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: 'Пользователь не найден' });
    }
    const user = userRes.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Неверный пароль' });
    }
    req.session.user = { id: user.id, name: user.name, email: user.email };
    res.json({ success: true });
  } catch (error) {
    console.error('DB Login Error:', error);
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

// Получить информацию о текущем пользователе
app.get('/api/me', (req, res) => {
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.json({ user: null });
  }
});

// Выход пользователя
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Удаление пользователя
app.post('/api/delete-user', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Не авторизован' });
  }
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.session.user.id]);
    res.json({ success: true }); // Сразу отправляем ответ клиенту
    req.session.destroy(() => {}); // Завершаем сессию асинхронно
  } catch (error) {
    console.error('DB Delete User Error:', error);
    res.status(500).json({ error: 'Ошибка удаления пользователя' });
  }
});



app.listen(PORT, () => {
  console.log(`✅ Сервер запущен: http://localhost:${PORT}`);
});
