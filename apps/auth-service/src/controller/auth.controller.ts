import { NextFunction, Request, Response } from "express";
import { sendOtp, trackOtpRequests } from "../utils/auth.helper";
import { validateRegistrationData } from "../utils/auth.helper";
import prisma from "../../../../packages/libs/prisma";
import { checkOtpRestrictions } from "../utils/auth.helper";
import { validationError } from "../../../../packages/error-handler";
// Register a new user
export const userRegistration = async (req: Request, res: Response, next: NextFunction) => {
try{
validateRegistrationData(req.body, "user")
const { name, email } = req.body;
const existingUser = await prisma.user.findUnique({ where: email})
if(existingUser){
    return next(new validationError("User already exists with this email!"));

};
await checkOtpRestrictions(email, next);
await trackOtpRequests(email, next);
await sendOtp(email, name, "user-activation-mail")
res.status(200).json({
    message: "OTP sent to email. Please verify your account."
})
}catch(error){
return next(error);
}
}