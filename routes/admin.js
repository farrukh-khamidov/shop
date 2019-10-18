const path = require('path')

const express = require('express')
const { body } = require('express-validator')

const adminController = require('../controllers/admin')
const isAuth = require('../middleware/is-auth')

const router = express.Router()

// /admin/add-product => GET
router.get('/add-product', isAuth, adminController.getAddProduct)

// /admin/products => GET
router.get('/products', isAuth, adminController.getProducts)

// /admin/add-product => POST
router.post('/add-product',[
    body('title')
        .isLength({ min: 3 })
        .isString()
        .trim()
        .withMessage('You can only enter string values for title.'),
    body('price')
        .isFloat()
        .withMessage('Price should be floating number.'),
    body('description', 'Description can not be empty.')
        .isLength({ min: 5, max: 400 })
        .trim()
], isAuth, adminController.postAddProduct)

router.get('/edit-product/:productId', isAuth, adminController.getEditProduct)

router.post('/edit-product', [
    body('title')
        .isLength({ min: 3 })
        .isString()
        .trim()
        .withMessage('You can only enter string values for title.'),
    body('price')
        .isFloat()
        .withMessage('Price should be floating number.'),
    body('description', 'Description can not be empty.')
        .isLength({ min: 5, max: 400 })
        .trim()
], isAuth, adminController.postEditProduct)

router.delete('/product/:productId', isAuth, adminController.deleteProduct)

module.exports = router  