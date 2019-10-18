const path = require('path')
const fs = require('fs')
// const https = require('https')

const express = require('express')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const session = require('express-session')
const MongoDBStore = require('connect-mongodb-session')(session)
const csrf = require('csurf')
const flash = require('connect-flash')
const multer = require('multer')
const helmet = require('helmet')
const copmression = require('compression')
const morgan = require('morgan')

const errorController = require('./controllers/error')
const shopController = require('./controllers/shop')
const isAuth = require('./middleware/is-auth')
const User = require('./models/user')

// console.log(process.env.NODE_ENV)

const MONGODB_URI = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0-xh6lx.mongodb.net/${process.env.MONGO_DEFAULT_DATABASE}`

const app = express()
const store = new MongoDBStore({
    uri: MONGODB_URI,
    collection: 'sessions'
})
const csrfProtection = csrf()

// const privateKey = fs.readFileSync('server.key')
// const certificate = fs.readFileSync('server.cert')

const fileStorage = multer.diskStorage({
    destination: (req, file, callback) => {
        callback(null, 'images')
    },
    filename: (req, file, callback) => {
        callback(null, new Date().toISOString().replace(/:/g, '_') + '-' + file.originalname)
    }
})

const fileFilter = (req, file, callback) => {
    if (file.mimetype === 'image/png' || file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg') {
        callback(null, true)
    } else {
        callback(null, false)
    }
}

app.set('view engine', 'ejs')
app.set('views', 'views')

const adminRoutes = require('./routes/admin')
const shopRoutes = require('./routes/shop')
const authRoutes = require('./routes/auth')

const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' })

app.use(helmet())
app.use(copmression())
app.use(morgan('combined', { stream: accessLogStream }))

app.use(bodyParser.urlencoded({ extended: false }))
app.use(multer({ storage: fileStorage, fileFilter }).single('image'))
app.use(express.static(path.join(__dirname, 'public')))
app.use('/images', express.static(path.join(__dirname, 'images')))

app.use(session({ secret: 'my secret', resave: false, saveUninitialized: false, store }))

app.use(flash())

app.use((req, res, next) => {
    res.locals.isAuthenticated = req.session.isLoggedIn
    next()
})

app.use((req, res, next) => {
    // throw new Error('Sync Dummy')
    if (!req.session.user) {
        return next()
    }
    User.findById(req.session.user._id)
        .then(user => {
            if (!user) {
                return next()
            }
            req.user = user
            next()
        })
        .catch(err => {
            next(new Error(err))
        })
})


app.post('/create-order', isAuth, shopController.postOrder)

app.use(csrfProtection)
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken()
    next()
})

app.use('/admin', adminRoutes)
app.use(shopRoutes)
app.use(authRoutes)

app.get('/500', errorController.get500)

app.use(errorController.get404)

app.use((error, req, res, next) => {
    // res.status(error.httpStatusCode).render(...)
    console.log(error)
    res.status(500).render('500', {
        title: 'Error',
        path: '/500',
        isAuthenticated: req.session.isLoggedIn
    })
    // res.redirect('/500')
})

mongoose
    .connect(MONGODB_URI, {
        useNewUrlParser: true,
        useCreateIndex: true,
        useFindAndModify: false,
        useUnifiedTopology: true
    })
    .then(result => {
        // https.createServer({ key: privateKey, cert: certificate }, app).listen(process.env.PORT || 3000);
        app.listen(process.env.PORT || 3000);
    })
    .catch(err => console.log(err))