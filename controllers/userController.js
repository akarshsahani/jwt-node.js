import UserModel from "../models/User.js";
import bcrypt from 'bcrypt'
import jwt from "jsonwebtoken"
import transporter from "../config/emailConfig.js";

class UserController{
    static userRegistration = async(req, res) => {
        const {name, email, password, password_confirmation, tc} = req.body
        const user = await UserModel.findOne({email:email})
        if(user){
            res.status(409).send({"status":"failed", "message":"Email already exist"})
        }
        else{
            console.log(name ? true : false);
            if(name && email && password && password_confirmation && tc){
                if(password===password_confirmation){
                   try {
                        const salt = await bcrypt.genSalt(10)
                        const hashPassword = await bcrypt.hash(password, salt)
                        const doc = new UserModel({
                            name:name,
                            email:email,
                            password:hashPassword,
                            tc:tc
                        })
                        await doc.save()
                        const saved_user = await UserModel.findOne({email:email})

                        // Generate JWT Token
                        const token = jwt.sign({userID:saved_user._id}, process.env.JWT_SECRET_KEY, {expiresIn: '1d'})

                        res.status(201).send({"status":"success", "message":"Registration Success", "token" : token})
                   } catch (error) {
                        console.log(error)
                        res.status(400).send({"status":"failed", "message":"Unable to Register"})
                   }
                }
                else{
                    res.status(400).send({"status":"failed", "message":"Password and confirm password doesn't match"})
                }
            }
            else{
                res.status(400).send({"status":"failed", "message":"All fields are required"})
            }
        }
    }


    static userLogin = async(req, res) => {
        try {
            const {email, password} = req.body
            if(email && password){
                const user = await UserModel.findOne({email:email})
                if(user != null){
                    const isMatch = await bcrypt.compare(password, user.password)
                    if((user.email === email) && isMatch){
                        
                        // generate jwt token
                        const token = jwt.sign({userID:user._id}, process.env.JWT_SECRET_KEY, {expiresIn: '1d'})

                        res.status(200).send({"status":"success", "message":"Login Success", "token": token})
                    }
                    else{
                        res.status(400).send({"status":"failsed", "message":"Email or password is not valid"})
                    }
                }
                else{
                    res.status(404).send({"status" : "failed", "message" : "you are not a regisered user"})
                }
            }
            else{
                res.status(401).send({"status" : "failed", "message" : "all fields are required"})
            }
        } catch (error) {
            console.log(error)
            res.status(400).send({"status": "failed", "message":"Unable to login"})
        }
    }


    static changeUserPassword = async(req, res) => {
        const {password, password_confirmation} = req.body
        if(password && password_confirmation){
            if(password !== password_confirmation){
                res.status(400).send({"status":"failed", "message":"new password and confirm new password doen't match"})
            }
            else{
                const salt = await bcrypt.genSalt(10)
                const newHashPassword = await bcrypt.hash(password, salt)
                // console.log(user)
                await UserModel.findByIdAndUpdate(req.user._id, {$set: {password: newHashPassword}})
                res.status(200).send({"status":"success", "message":"Password changed successfully"})
            }
        }
        else{
            res.status(400).send({"status":"failed", "message":"All fields are required"})
        }
    }


    static loggedUser = async(req, res) => {
        res.send({"user":req.user})
    }


    static sendUserPasswordResetEmail = async(req, res) => {
        const {email} = req.body
        console.log(email)
        
        try {
            if(email){
                const user = await UserModel.findOne({email:email})
                console.log(user)
                
                
                if(user){
                    const secret = user._id + process.env.JWT_SECRET_KEY
                    const token = jwt.sign({userID: user._id}, secret, {expiresIn: '15m'})
                    const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`
                    
                    // send email 
                    let info = await transporter.sendMail({
                        from: process.env.EMAIL_FROM,
                        to: "shailesh.devaraj@softsuave.org",
                        subject: "Akash Test - Password Reset",
                        html: `<a href=${link}>Click Here</a> to Reset your password`
                    })
    
                    console.log(link)
                    res.status(200).send({"status":"success", "message":"Password Reset Email Sent... Please check your Email", "info":info})
                }
                else{
                    res.status(401).send({"status":"failed", "message":"Email doesn't exist"})
                }
            }
            else{
                res.status(401).send({"status":"failed", "message":"Email Field is Required"})
            }
        } catch (error) {
            return res.status(400).send({message: error})
        }
    }

    static userPasswordReset = async(req, res) => {
        const {password, password_confirmation} = req.body
        const {id, token} = req.params
        const user = await UserModel.findById(id)
        const new_secret = user._id + process.env.JWT_SECRET_KEY

        try {
            jwt.verify(token, new_secret)
            if(password && password_confirmation){
                if(password === password_confirmation){
                    const salt = await bcrypt.genSalt(10)
                    const newHashPassword = await bcrypt.hash(password,salt)
                    await UserModel.findByIdAndUpdate(user._id, {$set: {password: newHashPassword}})
                    res.status(200).send({"status":"success", "message":"Password changed Successfully"})
                }
                else{
                    res.status(401).send({"status":"failed", "message":"new password and confirm new password doen't match"})
                }
            }
            else{
                res.status(401).send({"status":"failed", "message":"All fields are required"})
            }
        } catch (error) {
            console.log(error)
            res.status(401).send({"status":"failed", "message":"Invalid Token"})
        }
    }
}


export default UserController;