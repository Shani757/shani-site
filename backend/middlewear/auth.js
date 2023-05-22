const JWTService = require('../services/JWTservice')
const User = require('../models/users')
const userDTO = require('../dto/user')

const auth = async (req, res, next)=>{
    try {
        // 1. Validate access & refresh tokens
    const {refreshToken, accessToken} = req.cookies;
    if (!refreshToken || !accessToken){
        const error = {
            status: 401,
            message: 'UnAuthorized'
        }
        return next(error);
    }
    let _id;
    try {
        _id = JWTService.verifyAccessToken(accessToken)._id;
        
    } catch (error) {
        return next(error);
    }
    let user;
    try {
        user = await User.findOne({_id: _id});
        
    } catch (error) {
        return next(error);
    }    

    const userDto = new userDTO(user);
    req.user = userDto;
    next();
    } catch (error) {
        return next(error);
    }
    
}

module.exports = auth;