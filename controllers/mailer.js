import nodemailer from "nodemailer";
import Mailgen from "mailgen";

import ENV from '../config.js';

let nodeConfig = {
  host: "smtp.ethereal.email",
  port: 587,
  secure: false, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: ENV.EMAIL,
    pass: ENV.PASSWORD,
  },
}

let transporter = nodemailer.createTransport(nodeConfig);

let MailGenerator = new Mailgen({
    theme: "default",
    product: {
        name: "Mailgen",
        link: "https://mailgen.js/"
    }    
})

export const registerMail = async (req, res) => {
    const { username, userEmail, text, subject } = req.body;

    var email = {
        body: {
            name: username,
            intro: text || 'welcome to Maligen',
            outro: 'Need help, or have question? Just reply to this email, we\'d love to help.'
        }    
    }

    var emailBody = MailGenerator.generate(email);

    let message = {
        from: ENV.EMAIL,
        to: userEmail,
        subject: subject || 'Sigup Successful',
        html: emailBody
    }

    transporter.sendMail(message)
    .then(() => {
        return res.status(200).send({ msg: "You should receive an email from us" });
    })
    .catch(error => {
        return res.status(500).send({ error: "Error sending email" });
    })
}