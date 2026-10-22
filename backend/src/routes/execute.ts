import { Router, Response } from 'express';
import { AuthenticatedRequest } from '../types';
import { requireAuth, scanCodeForThreats } from '../security/securityMiddleware';

const router = Router();

router.use(requireAuth);

/**
 * Minimal compilable Phase 2 stub for `/api/execute`.
 * Will be expanded in Phase 5 & Phase 7 with full multi-layer child_process sandbox isolation,
 * Red-Team Cyber-Defense Simulator, and AI Security Reviewer.
 */
router.post('/scan', (req: AuthenticatedRequest, res: Response): void => {
    const code = typeof req.body?.code === 'string' ? req.body.code : '';
    const language =
        typeof req.body?.language === 'string' ? req.body.language : 'python';
    const result = scanCodeForThreats(code, language);
    res.json(result);
});

router.post('/', (req: AuthenticatedRequest, res: Response): void => {
    const code = typeof req.body?.code === 'string' ? req.body.code : '';
    const language =
        typeof req.body?.language === 'string' ? req.body.language : 'python';
    const scan = scanCodeForThreats(code, language);

    res.status(200).json({
        status: 'PHASE_5_SANDBOX_STUB',
        safe: scan.safe,
        threatsDetected: scan.threats,
        riskScore: scan.riskScore,
        message:
            'Execution endpoint mounted and authenticated. Full multi-layer sandbox engine activates in Phase 5.',
    });
});

export default router;