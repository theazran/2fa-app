const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    passwordHash: String,
    phone: String,
    otpEnabled: { type: Boolean, default: false },
    created: { type: Date, default: Date.now }
});

const accountSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    userId: { type: String, required: true },
    name: String,
    issuer: String,
    secret: String,
    type: { type: String, default: 'TOTP' },
    algorithm: String,
    digits: Number,
    period: Number,
    added: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Account = mongoose.model('Account', accountSchema);

const connectDB = async () => {
    if (process.env.MONGO_URI) {
        try {
            await mongoose.connect(process.env.MONGO_URI);
            console.log('MongoDB Connected');
            return true;
        } catch (err) {
            console.error('MongoDB Connection Error:', err);
            return false;
        }
    } else {
        console.log('No MONGO_URI provided. Using local JSON files.');
        return false;
    }
};

module.exports = { User, Account, connectDB };
