require("dotenv").config();

// DB 설정
var sequelize = require('./src/models/index.js').sequelize;

// express 설정
const express = require('express');
sequelize.sync(); 
const app = express();
const port = 3000;
app.use(express.json()); 
app.use(express.urlencoded( {extended : false } ));

app.get('/', (req, res) => {
  res.send('Hello, Express!');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// const indexRouter = require('./src/routes');
const authRouter = require('./src/routes/auth');

// app.use('/', indexRouter);
app.use('/auth', authRouter);

app.use((req, res, next) => { // 기본경로나 /user말고 다른곳 진입했을경우 실행
    res.status(404).send('Not Found');
});