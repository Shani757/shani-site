const Joi = require('joi')
const User = require('../models/users')
const bcrypt = require('bcryptjs')
const userDTO = require('../dto/user');
const JWTService = require('../services/JWTservice')
const RefreshToken = require('../models/token')
const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const authController = {
    async register(req, res, next) {
        // 1. Validate user input
        const userRegisterSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            name: Joi.string().max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().pattern(passwordPattern).required(),
            confirmPassword: Joi.ref('password'),
        })
        const {error} = userRegisterSchema.validate(req.body);
        // 2. if error in validation -> return error via middlewear
        if (error){
            return next(error);
        }
        // 3. if username or email already taken -> return error
        const {username, name, email, password} = req.body;

        // Check if email is not already registered
        try{
            const emailInUse = await User.exists({email});
            const usernameInUse = await User.exists({username});

            if (emailInUse){
                const error = {
                    status : 409,
                    message : 'Email already registered, use another'
                }
                return next(error);
            }
            if (usernameInUse){
                const error = {
                    status : 409,
                    message : 'Username not available, use another'
                }
                return next(error);
            }
        }
        catch(error) {
            return next(error);
            
        }

        // 4. password hash
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 5. store user data in database
        let accessToken;
        let refreshToken;
        let user;
        try{
            const userToRegister = new User ({
                username,
                email,
                name,
                password : hashedPassword
            });
            user = await userToRegister.save();

            //Token generation
            accessToken = JWTService.signAccessToken({_id: user._id}, '30m');
            
            refreshToken = JWTService.signRefreshToken({_id: user._id}, '60m');
        }
        catch(error){
            return next(error);
        }
        //Store refresh token in db
        await JWTService.storeRefreshToken(refreshToken, user._id);
        //Send token in cookies
        res.cookie('accessToken', accessToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true
            
        })
        res.cookie('refreshToken', refreshToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true
            
        })

        // 6. response send
        const userDto = new userDTO(user);
        return res.status(201).json({user: userDto, auth: true});
    },
    async login(req, res, next) {
        // 1. Validate user input
        const userLoginSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            password: Joi.string().pattern(passwordPattern).required()
        })
        // 2. if validation error, return error
        const {error} = userLoginSchema.validate(req.body);
        if (error) {
            return next(error);
        }
            const {username, password} = req.body;
        // 3. match username and password
        let user;
        try {
            // match username
            user = await User.findOne({username: username})
            if (!user) {
                const error = {
                    status : 401,
                    message : 'Invalid Username or Password'
                }
                return next(error);
            }
            // match password
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                const error = {
                    status: 401,
                    message: 'Invalid Username or Password'
                }
                return next(error);
            }
        }
        catch(error){
            return next(error);

        }
        const accessToken = JWTService.signAccessToken({_id: user._id}, '30m');
        const refreshToken = JWTService.signRefreshToken({_id: user._id}, '60m');
        // update refresh token in data base
        try{
            await RefreshToken.updateOne({
                _id: user._id
            },
            {token: refreshToken},
            {upsert: true}
            )

        }
        catch(error){
            return next(error);
        }

        //send cookies
        res.cookie('accessToken', accessToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
        })
        res.cookie('refreshToken', refreshToken, {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
        })
        const userDto = new userDTO(user);
        // 4. return response
        return res.status(200).json({user: userDto, auth: true})
    },
    async logout(req, res, next) {
        // 1. delete refresh token from db
        const {refreshToken} = req.cookies;
    
        try {
          await RefreshToken.deleteOne({token: refreshToken});
        } catch (error) {
          return next(error);
        }
    
        // delete cookies
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
    
        // 2. response
        res.status(200).json({ user: null, auth: false });
      },
    async refresh(req, res, next) {
        // 1. Get refreshToken from cookies
        const originalRefreshToken = req.cookies.refreshToken;
        
        let id;
        try {
            id = JWTService.verifyRefreshToken(originalRefreshToken)._id;
        } catch (e) {
            const error = {
                status: 401,
                message: 'Unauthorized'
            }
            return next(error);
        }
        // 2. verify refreshToken
        try {
            const match = RefreshToken.findOne({_id: id, token: originalRefreshToken});
        } catch (e) {
            const error = {
                status: 401,
                message: 'Unauthorized'
            }
            return next(error);
        }
        // 3. generate new token
        try {
            const accessToken = JWTService.signAccessToken({_id: id}, '30m')
            
            const refreshToken = JWTService.signRefreshToken({_id: id}, '60m')

            // 4. Update in db
            await RefreshToken.updateOne({_id: id}, {token: refreshToken});

            res.cookie('accessToken', accessToken, {
                maxAge: 1000 * 60 * 60 * 24,
                httpOnly: true
            })
            res.cookie('refreshToken', refreshToken, {
                maxAge: 1000 * 60 * 60 * 24,
                httpOnly: true
            })
        } catch (e) {
            return next(e);
        }
        // 5. reponse
        const user = await User.findOne({_id: id});
        const userDto = new userDTO(user);
        return res.status(200).json({user: userDto, auth: true});
    },
    
}



module.exports = authController;