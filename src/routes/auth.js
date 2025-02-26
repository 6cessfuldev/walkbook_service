const express = require('express');
const router = express.Router();
const { User } = require('../models'); 
const { verifyAccessToken, generateJWT } = require('../middlewares/auth');

// 로그인 처리 라우트
router.post('/signup', verifyAccessToken, async (req, res) => {
    try {
        const { provider, provider_id, email, name } = req.user;

        if (!id) {
            return res.status(400).json({ error: 'ID를 얻는데 실패했습니다.' });
        }

        // 아이디 중복 체크
        const existingUser = await User.findOne({
            where: {
                provider: req.user.provider,
                provider_id: req.user.provider_id,
            }
        });
        if (existingUser) {
            return res.status(400).json({ error: '이미 사용 중인 아이디입니다.' });
        }

        // 새 사용자 생성
        const newUser = await User.create({
            provider,
            provider_id,
            email,
            name,
        });

        // JWT 생성
        const jToken = generateJWT(newUser.id, newUser.provider);

        // 응답 데이터
        res.status(201).json({
            user: {
                id: newUser.id,
                username: newUser.username,
                name: newUser.name,
            },
            accessToken: jToken,
        });

    } catch (error) {
        console.error('Login failed:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

module.exports = router;