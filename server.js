const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');

const app = express();

app.set('view engine', 'ejs');

app.set('views', __dirname + '/views');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true
}));

app.use('/', authRoutes);

mongoose.connect('mongodb://localhost:27017/logincheck')
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((err) => {
    console.error('Failed to connect to MongoDB', err);
  });

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});
