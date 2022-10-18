import express from "express";
const router = express.Router();
import UserController from "../controllers/userController.js";
import checkUserAuth from "../middlewares/auth-middleware.js";

// Route Level Middleware - to protect route
router.use('/change-password', checkUserAuth)
router.get('/logged-user', checkUserAuth)


// Public Route
router.post('/register', UserController.userRegistration)
router.post('/login', UserController.userLogin)
router.post('/send-reset-password-email', UserController.sendUserPasswordResetEmail)
router.get('/reset-password/:id/:token', UserController.userPasswordReset)


// Protected Routes
router.post('/change-password', UserController.changeUserPassword)
router.get('/logged-user', UserController.loggedUser)


export default router