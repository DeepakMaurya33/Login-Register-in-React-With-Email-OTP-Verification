import UserModel from "../model/User.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import ENV from "../config.js";
import otpGenerator from "otp-generator";

export async function verifyUser(req, res, next){
    try {

        const { username } = req.method == "GET" ? req.query : req.body;
        let exist = await UserModel.findOne({ username });
        if(!exist) return res.status(404).send({ error : "Can't find User!"});
        next();

    }catch (error) {
        return res.status(404).send({ error: "Authentication Error"});
    }
}

export async function register(req, res) {
    try {
        const { username, password, profile, email } = req.body;

        const existUsername = UserModel.findOne({ username }).exec();
        const existEmail = UserModel.findOne({ email }).exec();

        Promise.all([existUsername, existEmail])
            .then(([usernameResult, emailResult]) => {
                if (usernameResult) {
                    throw { status: 400, message: "Please use a unique username" };
                }
                if (emailResult) {
                    throw { status: 400, message: "Please use a unique email" };
                }

                if (password) {
                    return bcrypt.hash(password, 10);
                } else {
                    throw { status: 400, message: "Password is required" };
                }
            })
            .then(hashedPassword => {
                const newUser = new UserModel({
                    username,
                    password: hashedPassword,
                    profile,
                    email
                });

                return newUser.save();
            })
            .then(() => {
                res.status(201).send({ msg: "User registered successfully" });
            })
            .catch(error => {
                if (error.status) {
                    res.status(error.status).send({ error: error.message });
                } else {
                    res.status(500).send({ error: "An error occurred during registration" });
                }
            });
    } catch (error) {
        return res.status(500).send({ error: error.message });
    }
}

export async function login(req, res) {
    const { username, password } = req.body;
    try {
        const user = await UserModel.findOne({ username }).exec();
        console.log("User found:", user);

        if (!user) {
            console.log("User not found");
            return res.status(404).send({ error: "Username not Found" });
        }

        const passwordCheck = await bcrypt.compare(password, user.password);
        console.log("Password check:", passwordCheck);

        if (!passwordCheck) {
            console.log("Password does not match");
            return res.status(400).send({ error: "Password does not Match" });
        }

        const token = jwt.sign({
            userId: user._id,
            username: user.username
        }, ENV.JWT_SECRET, { expiresIn: "24h" });

        console.log("Login successful, token generated");
        return res.status(200).send({
            msg: "Login Successful...!",
            username: user.username,
            token
        });
    } catch (error) {
        console.error("An error occurred during login:", error);
        return res.status(500).send({ error: "An error occurred during login" });
    }
}

export async function getUser(req, res) {
    const { username } = req.params;

    if (!username) {
        return res.status(400).send({ error: "Invalid Username" });
    }

    try {
        const user = await UserModel.findOne({ username }).exec();
        if (!user) {
            return res.status(404).send({ error: "Couldn't Find the User" });
        }

        const { password, ...rest } = Object.assign({}, user.toJSON()); // Convert Mongoose document to plain object
        return res.status(200).send(rest);
    } catch (error) {
        return res.status(500).send({ error: "Cannot Find User Data" });
    }
}

export async function updateUser(req, res) {
    try {
        const { userId } = req.user;
        if (!userId) {
            return res.status(400).json({ error: "User ID is required" });
        }

        const body = req.body;

        const result = await UserModel.updateOne({ _id: userId }, body);

        if (result.matchedCount === 0) {
            return res.status(404).json({ msg: "User not found" });
        }

        if (result.nModified === 0) {
            return res.status(200).json({ msg: "No changes made" });
        }

        return res.status(200).json({ msg: "Record updated...!" });

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
}

export async function generateOTP(req, res) {
    req.app.locals.OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false})
    res.status(201).send({ code: req.app.locals.OTP })
}

export async function verifyOTP(req, res) {
    const { code } = req.query;
    if(parseInt(req.app.locals.OTP) === parseInt(code)){
        req.app.locals.OTP = null;
        req.app.locals.resetSession = true;
        return res.status(201).send({ msg: "Verify Successfuly!"})
    }
    return res.status(400).send({ error: "Invalid OTP"})
}

export async function createResetSession(req, res) {
    if(req.app.locals.resetSession){
        return res.status(201).send({ flag: req.app.locals.resetSession})
    }
    return res.status(440).send({error : "Session expired!"})
}

export async function resetPassword(req, res) {
    try {
        
        if (!req.app.locals.resetSession) {
            return res.status(440).send({ error: "Session expired!" });
        }

        const { username, password } = req.body;

        const user = await UserModel.findOne({ username });

        if (!user) {
            return res.status(404).send({ error: "Username not found" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const updateResult = await UserModel.updateOne({ username: user.username }, { password: hashedPassword });

        if (updateResult.nModified === 0) {
            return res.status(500).send({ error: "Failed to update password" });
        }

        req.app.locals.resetSession = false;

        return res.status(201).send({ msg: "Record Updated...!" });

    } catch (error) {
        return res.status(500).send({ error });
    }
}