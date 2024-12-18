// notificationService.js
require('dotenv').config();
const nodemailer = require('nodemailer');
const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const transporter = nodemailer.createTransport({
    host: 'smtp.sendgrid.net',
    port: 587,
    secure: false,
    auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY
    }
});

// Updated notification service
const sendEmail = async (to, subject, text) => {
    if (!to || typeof to !== 'string') {
        console.error('Invalid email recipient:', to);
        return false;
    }

    const msg = {
        to: to.trim(),
        from: 'badisalikithasri@gmail.com', // Your verified SendGrid sender
        subject: subject || 'Food Donation Platform Notification',
        text: text || 'Notification from Food Donation Platform',
    };

    try {
        await sgMail.send(msg);
        console.log('Email sent successfully to:', to);
        return true;
    } catch (error) {
        console.error('SendGrid Error:', error);

        // Fallback to SMTP with error handling
        try {
            if (!transporter) {
                throw new Error('SMTP transporter not configured');
            }

            await transporter.sendMail({
                from: 'badisalikithasri@gmail.com',
                to: to.trim(),
                subject: subject || 'Food Donation Platform Notification',
                text: text || 'Notification from Food Donation Platform'
            });
            console.log('Email sent successfully via SMTP to:', to);
            return true;
        } catch (smtpError) {
            console.error('SMTP Error:', smtpError);
            return false;
        }
    }
};
async function sendSMS(to, message) {
    // Placeholder for SMS functionality
    console.log(`SMS would be sent to ${to}: ${message}`);
    return true;
}

module.exports = { sendEmail, sendSMS};

