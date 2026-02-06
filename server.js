const express = require('express');
const swaggerUI = require('swagger-ui-express');
const YAML = require('yamljs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const swaggerDocument = YAML.load('./swagger.yaml');

const app = express();
const port = process.env.PORT || 3000;

const SECRET_KEY = 'mysecretkey';

let users = [];

app.use(express.json());

app.post('/auth/register', async (req, res) => {
    const {
        username,
        email,
        password
    } = req.body;

    if (users.find(u => u.email === email)) {
        return res
            .status(400)
            .json({
                message: 'Email already exists'
            });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: users.length + 1,
        username,
        email,
        password: hashedPassword
    };

    users.push(newUser);

    res.status(201)
        .json({
            id: newUser.id,
            username: newUser.username,
            email: newUser.email
        });
});

app.post('/auth/login', async (req, res) => {
    const {
        email,
        password
    } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res
            .status(400)
            .json({
                message: 'Invalid credentials'
            });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res
            .status(400)
            .json({
                message: 'Invalid credentials'
            });
    }

    const token = jwt
        .sign({
            id: user.id,
            username: user.username,
            email: user.email
        }, SECRET_KEY, {
            expiresIn: '1h'
        });

    res.json({ token });
});

app.get('/auth/profile', (req, res) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res
            .status(401)
            .json({
                message: 'No token provided'
            });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt
            .verify(token, SECRET_KEY);
        const user = users
            .find(u => u.id === decoded.id);

        res.json({
            id: user.id,
            username: user.username,
            email: user.email
        });
    } catch (err) {
        res.status(401)
            .json({
                message: 'Invalid token'
            });
    }
});

app.post('/auth/logout', (req, res) => {
    const { token } = req.body;

    res.json({ message: 'You were logged out successfully!'});
});

app.post('/auth/refresh', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken)
        return res.status(401).json({ message: 'No refresh token' });

    const user = await User.findOne({ refreshToken });

    if (!user)
        return res.status(403).json({ message: 'Refresh token not valid' });

    try {
        jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        const newAccessToken = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_ACCESS_SECRET,
            { expiresIn: '15m' }
        );

        res.json({ accessToken: newAccessToken });

    } catch (err) {
        res.status(403).json({ message: 'Token expired or invalid' });
    }
});

app.post('/auth/forgot-password', (req, res) => {
    const { email } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '15m' });

    user.resetToken = resetToken;
    user.resetTokenExpires = Date.now() + 15 * 60 * 1000;

    res.json({
        message: 'Password reset link sent to email',
        resetToken
    });
});

app.post('/auth/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = users.find(
            u => u.id === decoded.id && u.resetToken === token && u.resetTokenExpires > Date.now()
        );

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        user.password = await bcrypt.hash(newPassword, 10);

        delete user.resetToken;
        delete user.resetTokenExpires;

        res.json({ message: 'Password has been reset successfully!' });
    } catch (err) {
        res.status(400).json({ message: 'Invalid or expired token' });
    }
});

app.post('/auth/verify-email', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ message: 'Verification token is required!' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = users.find(user => user.id === decoded.id);

        if (!user) {
            return res.status(404).json({ message: 'User was not found' });
        }

        if (user.isEmailVerified) {
            return res.json({ message: 'E-mail is already verified' });
        }

        user.isEmailVerified = true;
        res.json({ message: 'E-mail has been verified successfully!' });
    } catch (err) {
        return res.status(404).json({ message: 'Invalid or expired token' });
    }

    res.json({ message: 'E-mail verified successfully!' });
});


app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument));

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
