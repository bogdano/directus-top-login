import { defineEndpoint } from '@directus/extensions-sdk';
import jwt from 'jsonwebtoken';
import { nanoid } from 'nanoid';
import ms from 'ms';

export default defineEndpoint((router, { env, database, logger }) => {
    router.post('/', async (req, res) => {
        try {
            const { userId, otp } = req.body;

            if (!userId || !otp) {
                return res.status(400).json({
                    message: 'userId and otp are required',
                });
            }

            // Fetch user with necessary fields
            const user = await database
                .select('id', 'role', 'otp', 'otp_expires', 'otp_attempts')
                .from('directus_users')
                .where('id', userId)
                .first();

            if (!user) {
                return res.status(403).json({
                    message: 'Invalid user',
                });
            }

            // Check OTP attempts
            if (user.otp_attempts >= 3) {
                return res.status(403).json({
                    message: 'Too many attempts',
                    step: 'enter-email'
                });
            }

            // Validate OTP
            if (user.otp !== otp) {
                // Increment attempts
                await database('directus_users')
                    .where('id', userId)
                    .increment('otp_attempts', 1);

                return res.status(403).json({
                    message: 'Invalid OTP',
                });
            }

            // Check OTP expiration
            if (new Date(user.otp_expires) < new Date()) {
                return res.status(403).json({
                    message: 'OTP expired',
                    step: 'enter-email'
                });
            }

            // Base token payload
            const tokenPayload = {
                id: user.id,
                role: user.role,
                app_access: false,
                admin_access: false,
            };

            // Generate refresh token
            const refreshToken = nanoid(64);
            const refreshTokenExpiration = new Date(
                Date.now() + getMilliseconds(env['REFRESH_TOKEN_TTL'] || '7d')
            );

            // Add session to token payload only if in session mode
            if (req.body.session) {
                Object.assign(tokenPayload, { session: refreshToken });
            }

            // Generate access token
            const TTL = env[req.body.session ? 'SESSION_COOKIE_TTL' : 'ACCESS_TOKEN_TTL'] || '15m';
            const accessToken = jwt.sign(tokenPayload, env['SECRET'], {
                expiresIn: TTL,
                issuer: 'directus',
            });

            // Store refresh token in sessions table
            await database('directus_sessions').insert({
                token: refreshToken,
                user: user.id,
                expires: refreshTokenExpiration,
                ip: req.ip,
                user_agent: req.get('user-agent'),
                origin: req.get('origin'),
            });

            // Clean up expired sessions
            await database('directus_sessions')
                .delete()
                .where('expires', '<', new Date());

            // Reset OTP fields
            await database('directus_users')
                .where('id', userId)
                .update({
                    last_access: new Date(),
                    otp: null,
                    otp_expires: null,
                    otp_attempts: 0,
                    // In my usecase, OTP verification counts for account verification
                    status: 'active',
                });

            // Set cookies if in session mode
            if (req.body.session) {
                res.cookie('directus_refresh_token', refreshToken, {
                    httpOnly: true,
                    secure: env['NODE_ENV'] === 'production',
                    sameSite: 'strict',
                    expires: refreshTokenExpiration,
                });
            }

            return res.json({
                data: {
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    expires: getMilliseconds(TTL),
                    id: user.id,
                }
            });

        } catch (error) {
            logger.error(error);
            return res.status(500).json({
                message: 'Internal server error',
            });
        }
    });
});

function getMilliseconds(time: string, fallback = 0) {
    try {
        return ms(time);
    } catch {
        return fallback;
    }
}
