const crypto = require('crypto')

const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const sendgridTransport = require('nodemailer-sendgrid-transport')
const { validationResult } = require('express-validator')

const User = require('../models/user')

const transporter = nodemailer.createTransport(sendgridTransport({
    auth: {
        api_key: process.env.SENDGRID_API_KEY
    }
}))

exports.getLogin = (req, res, next) => {
    let message = req.flash('error')
    message = message.length > 0 ? message[0] : null
    res.render('auth/login', {
        title: 'Login',
        path: '/login',
        errorMessage: message,
        oldInput: {
            email: '', 
            password: ''
       },
       validationErrors: []
    })
}

exports.getSignup = (req, res, next) => {
    let message = req.flash('error')
    message = message.length > 0 ? message[0] : null
    res.render('auth/signup', {
        title: 'Signup',
        path: '/signup',
        errorMessage: message,
        oldInput: {
            email: '', 
            password: '', 
            confirmPassword: ''
       },
       validationErrors: []
    })
}

exports.postLogin = (req, res, next) => {
    const email = req.body.email
    const password = req.body.password

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            path: '/login',
            title: 'Login',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email, 
                password
           },
           validationErrors: errors.array()
        });
    }
    User.findOne({ email })
        .then(user => {
            if (!user) {
                req.flash('error', 'Invalid email or password.')
                return res.redirect('/login')
            }
            bcrypt.compare(password, user.password)
                .then(doMatch => {
                    if (doMatch) {
                        req.session.isLoggedIn = true
                        req.session.user = user
                        return req.session.save(err => {
                            res.redirect('/')
                        })
                    }
                    req.flash('error', 'Invalid email or password.')
                    res.redirect('/login')
                })
                .catch(err => {
                    console.log(err)
                    res.redirect('/login')
                })
        })
        .catch(err => {
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}

exports.postSignup = (req, res, next) => {
    const email = req.body.email
    const password = req.body.password
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).render('auth/signup', {
            title: 'Signup',
            path: '/signup',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                 email, 
                 password, 
                 confirmPassword: req.body.confirmPassword
            },
            validationErrors: errors.array()
        })
    }
    return bcrypt.hash(password, 12).then(hashedPassword => {
        const user = new User({
            email,
            password: hashedPassword,
            cart: { items: [] }
        })
        return user.save()
    })
        .then(() => {
            res.redirect('/login')
            return transporter.sendMail({
                to: email,
                from: 'shop@node-complete.com',
                subject: 'Signup succeded!',
                html: '<h1>You successfully signed up!</h1>'
            })
        })
        .catch(err => {
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}

exports.postLogout = (req, res, next) => {
    req.session.destroy((err) => {
        console.log(err)
        res.redirect('/')
    })
}

exports.getReset = (req, res, next) => {
    let message = req.flash('error')
    message = message.length > 0 ? message[0] : null
    res.render('auth/reset', {
        title: 'Reset Password',
        path: '/reset',
        errorMessage: message
    })
}

exports.postReset = (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if (err) {
            console.log(err)
            return res.redirect('/reset')
        }
        const token = buffer.toString('hex')
        User.findOne({ email: req.body.email })
            .then(user => {
                if (!user) {
                    req.flash('error', 'No account with that email found!')
                    return res.redirect('/reset')
                }
                user.resetToken = token
                user.resetTokenExpiration = Date.now() + 3600000
                return user.save()
            })
            .then(result => {
                res.redirect('/')
                transporter.sendMail({
                    to: req.body.email,
                    from: 'shop@node-complete.com',
                    subject: 'Password Reset',
                    html: `
                        <p>You requested a password reset</p>
                        <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
                    `
                })
            })
            .catch(err => {
                const error =  new Error(err) 
                error.httpStatusCode = 500
                return next(error)
            })
    })
}

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token
    User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
        .then(user => {
            let message = req.flash('error')
            message = message.length > 0 ? message[0] : null
            res.render('auth/new-password', {
                title: 'New Password',
                path: '/new-password',
                errorMessage: message,
                userId: user._id.toString(),
                passwordToken: token
            })
        })
        .catch(err => {
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}

exports.postNewPassword = (req, res, next) => {
    const newPassword = req.body.password
    const userId = req.body.userId
    const passwordToken = req.body.passwordToken
    let resetUser

    User.findOne({ resetToken: passwordToken, resetTokenExpiration: { $gt: Date.now() }, _id: userId })
        .then(user => {
            resetUser = user
            return bcrypt.hash(newPassword, 12)
        })
        .then(hashedPassword => {
            resetUser.password = hashedPassword
            resetUser.resetToken = undefined
            resetUser.resetTokenExpiration = undefined
            return resetUser.save()
        })
        .then(result => {
            res.redirect('/login')
        })
        .catch(err => {
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}