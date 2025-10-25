import user from  "../models/userModel.js"
import asyncHandler from "../middleware/asycHandler.js";
import bcrypt from "bcryptjs";
import createToken from "../utils/createToken.js";

const createUser = asyncHandler (async(req, res) =>{
    const {username, email, password} = req.body;

    // Validate input fields
    if(!username || !email || !password){
        throw new Error("Please fill in all the fields");
    };

    // Check if user already exists
    const userExists = await user.findOne({email})
    if(userExists) res.status(400).send("user already exists");

    // Make th password more secure
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt)

    // new user
    const newUser = new user({username, email, password: hashPassword})
    try{
        await newUser.save();
        createToken(res, newUser._id);

        res.status(201).json({
            _id: newUser._id, 
            username: newUser.username, 
            email: newUser.email,
            isAdmin: newUser.isAdmin,
        })
    }catch (error){
        throw new Error('Invalid user data')
    }
})

const loginUser = asyncHandler (async(req, res) =>{
    const {email, password} = req.body;

    const exsistingUser = await user.findOne({email});

    if(exsistingUser){
        const isPasswordValid = await bcrypt.compare(password, exsistingUser.password)

        if(isPasswordValid){
            createToken(res, exsistingUser._id);

            res.status(201).json({
                _id: exsistingUser._id, 
                username: exsistingUser.username, 
                email: exsistingUser.email,
                isAdmin: exsistingUser.isAdmin,
            });
            return // Exit the function after sending the response
        };
    }
});


const logoutCurrentUser = asyncHandler (async(req, res) =>{
    res.cookie('token', '', {
        httpOnly: true,
        expires: new Date(0)
    })
    res.status(200).json({message: "Logout successfully!"})
})

const getAllUsers = asyncHandler (async(req, res) =>{
    const users = await user.find({});
    res.json(users); 
})

const getCurrentUserProfile = asyncHandler (async(req, res) =>{
    const foundUser = await user.findById(req.user._id);
    if(foundUser){
        res.json({
            _id: foundUser._id,
            username: foundUser.username,
            email: foundUser.email,
        })
    }else{
        res.status(404);
        throw new Error('user not found')
    }
})


const updateCurrentUserProfile = asyncHandler (async(req, res) =>{
    const foundUser = await user.findById(req.user._id);
    if(foundUser){
        foundUser.username = req.body.username || foundUser.username;
        foundUser.email = req.body.email || foundUser.email; 
        
        if(req.body.password){
            foundUser.password = req.body.password;
        }

        const updateUser = await user.save();

        res.json({
            _id: updateUser._id,
            username: updateUser.username,
            email: updateUser.email,
            isAdmin: updateUser.isAdmin,
        })

    }else{
        res.status(404);
        throw new Error('user not found')
    }
});

export {
    createUser, 
    loginUser, 
    logoutCurrentUser, 
    getAllUsers,
    getCurrentUserProfile,
    updateCurrentUserProfile,
}; 