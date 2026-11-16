/**
 * Vercel Function: POST /api/password-check
 *
 * A mesma validação do servidor local (server/), publicada junto com o
 * site. É stateless: avalia a senha contra o padrão e o Have I Been
 * Pwned e responde. Cadastro e login com servidor precisam de banco de
 * dados e, por isso, existem só na demo local (npm run demo).
 */

import { createAuthService } from '../server/auth-service.mjs';
import { createRequestHandler } from '../server/http-handler.mjs';

export default createRequestHandler(createAuthService(), { routes: ['password-check'] });
