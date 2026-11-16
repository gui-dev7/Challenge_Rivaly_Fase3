/**
 * Vercel Function: GET /api/health
 * Diz ao site quais rotas de servidor existem neste ambiente.
 */

import { createAuthService } from '../server/auth-service.mjs';
import { createRequestHandler } from '../server/http-handler.mjs';

export default createRequestHandler(createAuthService(), { routes: ['health', 'password-check'] });
