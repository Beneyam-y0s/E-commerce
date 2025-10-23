import jwt from "jsonwebtoken";
import user from "../models/userModel.js";
import asyncHandler from "./asycHandler.js";

const authenticate = asyncHandler(async (req, res, next) => {
    let token;


    //read the jwt from the jwt cookie
    token = req.cookie.jwt;
    if(token){
        try{
            const decoded = jwt.verify(token, process.env.JWT_SECRET );
            req.user = await user.findById(decoded.userId).select('-password');
            next();
        }catch (error){
            res.status(401);
            throw new Error("Not Authorized, token faild")
        }
    }else{
        res.status(401);
        throw new Error("Not Authorized, token faild")
    }
});