const mongoose = require('mongoose')    
const fileHelper = require('../util/file')

const { validationResult } = require('express-validator')

const Product = require('../models/product')

exports.getAddProduct = (req, res, next) => {
    res.render('admin/edit-product', {
        title: 'Add Product',
        path: '/admin/add-product',
        editing: false,
        hasError: false,
        errorMessage: null,
        validationErrors: []
    })
}

exports.postAddProduct = (req, res, next) => {
    const title = req.body.title
    const image = req.file
    const description = req.body.description
    const price = req.body.price
    const errors = validationResult(req)
    if (!image) {
        return res.status(422).render('admin/edit-product', {
            product: {
                title, 
                price,
                description
            },
            title: 'Add Product',
            path: '/admin/add-product',
            editing: false,
            hasError: true,
            errorMessage: 'Attached file is not an image.',
            validationErrors: []
        })
    }
    if (!errors.isEmpty()) {
        return res.status(422).render('admin/edit-product', {
            product: {
                title,
                image,
                price,
                description
            },
            title: 'Add Product',
            path: '/admin/add-product',
            editing: false,
            hasError: true,
            errorMessage: errors.array()[0].msg,
            validationErrors: errors.array()
        })
    }

    const imageUrl = image.path
    const product = new Product({
        // _id: new mongoose.Types.ObjectId('5d9447c05afb542c4cbb28f9'),
        title,
        price,
        description,
        imageUrl,
        userId: req.user
    })
    product
        .save()
        .then(result => {
            console.log('Created Product')
            res.redirect('/admin/products')
        })
        .catch(err => {
            // return res.status(500).render('admin/edit-product', {
            //     product: {
            //         title,
            //         imageUrl,
            //         price,
            //         description
            //     },
            //     title: 'Add Product',
            //     path: '/admin/add-product',
            //     editing: false,
            //     hasError: true,
            //     errorMessage: 'Database operation failed, please try again.',
            //     validationErrors: []
            // })
            // res.redirect('/500')
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}

exports.getEditProduct = (req, res, next) => {
    const editMode = req.query.edit
    if (!editMode) {
        return res.redirect('/')
    }
    const productId = req.params.productId
    Product.findById(productId)
        .then(product => {
            if (!product) {
                return res.redirect('/')
            }
            res.render('admin/edit-product', {
                product,
                title: 'Edit Product',
                path: '/admin/edit-product',
                editing: editMode,
                hasError: false,
                errorMessage: null,
                validationErrors: []
            })
        }).catch(err => {
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}

exports.postEditProduct = (req, res, next) => {
    const productId = req.body.productId
    const updatedTitle = req.body.title
    const updatedPrice = req.body.price
    const image = req.file
    const updatedDescription = req.body.description

    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).render('admin/edit-product', {
            product: {
                title: updatedTitle,
                price: updatedPrice,
                description: updatedDescription,
                _id: productId
            },
            title: 'Edit Product',
            path: '/admin/add-product',
            editing: true,
            hasError: true,
            errorMessage: errors.array()[0].msg,
            validationErrors: errors.array()
        })
    }
    Product.findById(productId)
        .then(product => {
            if (product.userId.toString() !== req.user._id.toString()) {
                return res.redirect('/')
            }
            product.title = updatedTitle
            product.price = updatedPrice
            if (image) {
                fileHelper.deleteFile(product.imageUrl)
                product.imageUrl = image.path
            }
            product.description = updatedDescription
            return product.save().then(result => {
                console.log('UPDATED PRODUCT!')
                res.redirect('/admin/products')
            })
        })
        .catch(err => {
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}

exports.deleteProduct = (req, res, next) => {
    const productId = req.params.productId
    Product.findById(productId)
    .then(product => {
        if (!product) {
            return new Error('Product not found!')
        }
        fileHelper.deleteFile(product.imageUrl)
        return  Product.deleteOne({ _id: productId, userId: req.user._id })
    })
    .then(() => {
        const updatedCartItems = req.user.cart.items.filter(item => item.productId.toString() !== productId.toString())
        req.user.cart.items = updatedCartItems
        req.user.save()
        console.log('DESTROYED PRODUCT!')
        res.status(200).json({
            message: 'Success!'
        })
    })
    .catch(err => {
        res.status(500).json({
            message: 'Deleting product failed!'
        })
    })    
}

exports.getProducts = (req, res, next) => {
    Product.find({ userId: req.user._id })
        .then(products => {
            res.render('admin/products', {
                products,
                title: 'Admin Products',
                path: '/admin/products'
            })
        })
        .catch(err => {
            const error =  new Error(err) 
            error.httpStatusCode = 500
            return next(error)
        })
}