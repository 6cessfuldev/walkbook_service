const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwkToPem = require("jwk-to-pem");

require("dotenv").config();

const secretKey = process.env.AUTH_SECRET_KEY;

// loginType에 따라 accessToken을 사용하여 검증
const verifyAccessToken = async (req, res, next) => {
    try {
        const code = req.body.code;
        const provider = req.body.provider;

        if (!code) {
            return res.status(401).json({ error: 'No token provided' });
        }

        switch (provider) {
            case 'google':
                await verifyGoogleAccessToken(req, res, next);
                break;
            case 'kakao':
                await verifyKakaoAccessToken(req, res, next);
                break;
            case 'naver':
                await verifyNaverAccessToken(req, res, next);
                break;
            case 'apple':
                await verifyAppleAccessToken(req, res, next);
                break;
            default:
                return res.status(400).json({ error: 'Invalid provider' });
        }
    } catch (error) {
        console.error('Token verification failed:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Google의 accessToken을 사용한 검증
const verifyGoogleAccessToken = async (req, res, next) => {
    try {
        const accessToken = req.body.code;
        
        if (!accessToken) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Google의 userinfo endpoint로 직접 요청
        const response = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });

        // 사용자 정보 저장
        req.user = {
            provider_id: response.data.id,
            provider: req.body.provider,
            id: response.data.id,
            email: response.data.email,
            name: response.data.name
        };
        
        next();
    } catch (error) {
        console.error('Token verification failed:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// kakao accessToken을 사용한 검증
const verifyKakaoAccessToken = async (req, res, next) => {
    try {
        const accessToken = req.body.code;

        const response = await axios.get('https://kapi.kakao.com/v2/user/me', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });

        req.user = {
            provider_id: response.data.id,
            provider: req.body.provider,
            id: response.data.id,
            email: response.data.kakao_account?.email,
            name: response.data.properties?.nickname
        };

        next();
    } catch (error) {
        console.error('Kakao token verification failed:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// naver accessToken을 사용한 검증
const verifyNaverAccessToken = async (req, res, next) => {
    try {
        const accessToken = req.body.code;

        const response = await axios.get('https://openapi.naver.com/v1/nid/me', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });

        if (response.data.resultcode !== '00') {
            throw new Error('Token verification failed');
        }

        req.user = {
            provider_id: response.data.response.id,
            provider: req.body.provider,
            email: response.data.response.email,
            name: response.data.response.name,
            
        };

        next();
    } catch (error) {
        console.error('Naver token verification failed:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// apple idToken 사용한 검증
const verifyAppleAccessToken = async (req, res, next) => {
    try {
        const idToken = req.body.code;

        const userId = (await verifyIdToken(idToken))?.sub;

        if (!userId) {
            throw new Error("Invalid IdToken");
        }

        req.user = {
            provider_id: userId,
            provider: req.body.provider,
        };

        next();
    } catch (error) {
        console.error('Apple token verification failed:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// idToken 검증 및 정보 추출
async function verifyIdToken(idToken) {
    try {
        const decodedHeader = jwt.decode(idToken, { complete: true });
        if (!decodedHeader) throw new Error("Invalid token format");

        const kid = decodedHeader.header.kid;
        const alg = decodedHeader.header.alg;

        // Apple의 공개 키 가져오기
        const applePublicKey = await getApplePublicKey(kid);

        // 공개 키를 사용하여 JWT 검증
        const verifiedToken = jwt.verify(idToken, applePublicKey, {
            algorithms: [alg],
            issuer: 'https://appleid.apple.com',
            audience: 'com.iosyuk.walkbook',
        });

        return verifiedToken;
    } catch (error) {
        console.error("idToken 검증 실패:", error.message);
        throw new Error("Invalid Apple idToken");
    }
}


// Apple의 공개 키(JWK) 가져오기
async function getApplePublicKey(kid) {
    try {
        const response = await axios.get("https://appleid.apple.com/auth/keys");
        const keys = response.data.keys;

        const key = keys.find((key) => key.kid === kid);
        if (!key) throw new Error("Invalid key ID");
        
        const publicKey = jwkToPem(key);
        return publicKey;
    } catch (error) {
        console.error("Apple JWK 가져오기 실패:", error);
        throw new Error("Failed to fetch Apple public keys");
    }
}


// JWT 발급
const generateJWT = (id, provider) => {
    try {
        const jToken = jwt.sign({
            sub: id,
            provider: provider,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
            iss: 'walkbook',
            aud: 'walkbook-app'
        }, secretKey);

        return jToken;
    } catch (error) {
        console.error('generate JWT Error:', error);
        res.status(401).json({ error: 'generate JWT Error' });
    }
}

// 서비스 서버에서 발급한 JWT 검증
const verifyJWT = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];

        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, secretKey);

        if (decoded.exp < Math.floor(Date.now() / 1000)) {
            return res.status(401).json({ error: 'Token has expired' });
        }

        req.user = {
            id: decoded.sub,
            name: decoded.name,
            email: decoded.email
        };

        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token has expired' });
        }
        console.error('JWT Verification Error:', error);
        res.status(500).json({ error: 'Failed to verify token' });
    }
};

module.exports = {
    verifyAccessToken, generateJWT, verifyJWT
};