const express = require('express');
const router = express.Router();
const authController = require('../controlller/authController');
const blogController = require('../controlller/blogController');
const commentController = require('../controlller/commentController')
const auth = require('../middlewear/auth');
// testing
router.get('/test', (req, res) =>{
    res.json({msg: 'working!'})
})


// user

// register
router.post('/register', authController.register)
// login
router.post('/login', authController.login)
// logout
router.post('/logout', auth, authController.logout)
// refresh
router.get('/refresh', authController.refresh)

// blog
// create
router.post('/blog', auth, blogController.create)
//all blogs
router.get('/blog/all', auth, blogController.getAll)
// blog by id
router.get('/blog/:id', auth, blogController.getById)
// update
router.put('/blog', auth, blogController.update)
// delete
router.delete('/blog/:id', auth, blogController.delete)

// comment
// create comment

router.post('/comment', auth, commentController.create)

// read comments by blog id

router.get('/comment/:id', auth, commentController.getById)

module.exports = router;