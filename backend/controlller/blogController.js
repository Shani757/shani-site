const Joi = require('joi');
const fs = require('fs');
const Blog = require('../models/blog')
const Comment = require('../models/comment')
const {BACKEND_SERVER_PATH} = require('../config/index')
const BlogDTO = require('../dto/blog');
const BlogDetailsDTO = require('../dto/blog-details')
const mongodbIdPattern = /^[0-9a-fA-F]{24}$/;

const blogController = {
    async create(req, res, next) {
        // 1. validate req body
        // client side -> base 64 encoded string -> decode -> store -> save phto's path in db
        const createBlogSchema = Joi.object({
            title: Joi.string().required(),
            author: Joi.string().regex(mongodbIdPattern).required(),
            content: Joi.string().required(),
            photo: Joi.string().required()
        });
        const {error} = createBlogSchema.validate(req.body);

        if (error) {
            return next(error)
        }
        const {title, author, content, photo} = req.body;
        // read as buffer
        const buffer = Buffer.from(photo.replace(/^data:image\/(png|jpg|jpeg);base64,/, ''), 'base64')
        // allot a random name 
        const imagePath = `${Date.now()}-${author}`;
        // save locally
        try {
            fs.writeFileSync(`storage/${imagePath}.png`, buffer);
        } catch (error) {
            return next(error)
        }
        // save blog in db
        let newBlog;
        try {
            newBlog = new Blog({
                title,
                author,
                content,
                photoPath: `${BACKEND_SERVER_PATH}/storage/${imagePath}`
            });
            await newBlog.save();
        } catch (error) {
            return next(error)
        }
        // 2. handle photo storage, naming
        // 3. add to db
        // 4. return response
        const blogDto = new BlogDTO(newBlog);
        return res.status(201).json({blog: blogDto});
    },
    async getAll(req, res, next) {
        try {
            const blogs = await Blog.find({});

            const blogsDto = [];

            for(let i=0; i < blogs.length; i++){
                const dto = new BlogDTO(blogs[i]);
                blogsDto.push(dto);
            }
            return res.status(200).json({blogs: blogsDto});
        } catch (error) {
            return next(error);
        }
    },
    async getById(req, res, next) {
        //valodate id
        const getByIdSchema = Joi.object({
            id: Joi.string().regex(mongodbIdPattern).required(),

        })
        const {error} = getByIdSchema.validate(req.params);
        if(error){
            return next(error);
        }
        let blog;
        const {id} = req.params;
        try {
            blog = await Blog.findOne({_id: id}).populate("author");
        } catch (error) {
            return next(error);
        }
        //response
        const blogDto = new BlogDetailsDTO(blog);
        return res.status(200).json({blog: blogDto})
    },
    async update(req, res, next) {
        // validate
        const updateBlogSchema = Joi.object({
            title: Joi.string().required(),
            content: Joi.string().required(),
            author: Joi.string().regex(mongodbIdPattern).required(),
            blogId: Joi.string().regex(mongodbIdPattern).required(),
            photo: Joi.string()
        });
        const {error} = updateBlogSchema.validate(req.body);

        const {title, content, author, blogId, photo} = req.body;

        // delete old photo
        let blog;
        try {
            blog = await Blog.findOne({_id: blogId})
            
        } catch (error) {
            return next(error)
        }
        if(photo) {
            let previousPhoto = blog.photoPath;
            previousPhoto = previousPhoto.split('/').at(-1);
            //delete photo
            fs.unlinkSync(`storage/${previousPhoto}.png`);
            
            // save new photo
            const buffer = Buffer.from(photo.replace(/^data:image\/(png|jpg|jpeg);base64,/, ''), 'base64')
        // allot a random name 
        const imagePath = `${Date.now()}-${author}`;
        // save locally
        try {
            fs.writeFileSync(`storage/${imagePath}.png`, buffer);
        } catch (error) {
            return next(error)
        }
        await Blog.updateOne({_id: blogId},
            {title, content, photoPath: `${BACKEND_SERVER_PATH}/storage/${imagePath}`}
            );
        }
        else{
            await Blog.updateOne({_id: blogId},
                {title, content}
                );
        }
        return res.status(200).json({message: 'Blog updated!'})
    },
    async delete(req, res, next) {
        // validate id
        const deleteBlogSchema = Joi.object({
            id: Joi.string().regex(mongodbIdPattern).required(),
            
        });
        const {error} = deleteBlogSchema.validate(req.params);
        
        const {id} = req.params;
        //delete blog
        try {
            await Blog.deleteOne({_id: id})

            //delete comments on that blog
            await Comment.deleteMany({blog: id})
        } catch (error) {
            return next(error);
        }
        return res.status(200).json({message: 'Blog deleted!'})
    },

}


module.exports = blogController;