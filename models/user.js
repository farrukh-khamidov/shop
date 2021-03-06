const mongoose = require('mongoose')

const Order = require('./order')

const Schema = mongoose.Schema

const userSchema = new Schema({
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    resetToken: String,
    resetTokenExpiration: Date,
    cart: {
        items: [
            {
                productId: { type: Schema.Types.ObjectId, ref: 'Product', required: true },
                quantity: { type: Number, required: true }
            }
        ]
    }
})

userSchema.methods.addToCart = function (product) {
    const cartProductIndex = this.cart.items.findIndex(cp => {
        return cp.productId.toString() === product._id.toString()
    })
    let newQuantity = 1

    const updatedCartItems = [...this.cart.items]
    if (cartProductIndex >= 0) {
        newQuantity = this.cart.items[cartProductIndex].quantity + 1
        updatedCartItems[cartProductIndex].quantity = newQuantity
    } else {
        updatedCartItems.push({
            productId: product._id,
            quantity: newQuantity
        })
    }
    const updatedCart = { items: updatedCartItems }
    this.cart = updatedCart
    return this.save()
}

userSchema.methods.removeFromCart = function (productId) {
    const updatedCartItems = this.cart.items.filter(item => item.productId.toString() !== productId.toString())
    this.cart.items = updatedCartItems
    return this.save()
}

userSchema.methods.clearCart = function () {
    this.cart = { items: [] }
    return this.save()
}

userSchema.methods.getOrders = function () {
    return Order
        .find({ 'user.userId': this._id })
}

module.exports = mongoose.model('User', userSchema)

// const mongodb = require('mongodb')
// const { getDb } = require('../util/database')

// class User {
//     constructor(username, email, cart, id) {
//         this.name = username
//         this.email = email
//         this.cart = cart // {items: []}
//         this._id = id
//     }

//     save() {
//         const db = getDb()
//         db.collection('users').insertOne(this)
//             .then(result => {
//                 // console.log(result)
//             })
//             .catch(err => console.log(err))
//     }

//     addToCart(product) {

//     }



//     deleteItemFromCart(productId) {
//         
//     }




//     static findById(userId) {
//         const db = getDb()
//         return db.collection('users')
//             .findOne({ _id: new mongodb.ObjectId(userId) })
//     }
// }

// module.exports = User