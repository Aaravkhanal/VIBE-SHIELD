/** Build metric reasons from a detector's observed probe, never from its title. */
export function observedWebCvss({ metrics, request, role, observation, impacts = {}, boundary = null }) {
    if (!request || !role || !observation) throw new Error('CVSS assessment needs request, role, and observation');
    const impactReason = (name, value) => impacts[name] || (value === 'NONE'
        ? `The ${observation} did not demonstrate ${name} impact.`
        : null);
    return {
        metrics,
        reasons: {
            attackVector: `The tested attack used a network request: ${request}.`,
            attackComplexity: metrics.attackComplexity === 'LOW'
                ? `The ${observation} was repeatable under controlled requests without a special condition.`
                : `The ${observation} required an additional condition recorded by this detector.`,
            privilegesRequired: `The probe ran as ${role}; this is the access required for the observed behavior.`,
            userInteraction: metrics.userInteraction === 'REQUIRED'
                ? `The observed impact requires a user to open or act on the crafted content.`
                : `The ${observation} occurred in the scanner request without another user's action.`,
            scope: boundary || `The ${observation} did not demonstrate a change of security authority.`,
            confidentiality: impactReason('confidentiality', metrics.confidentiality),
            integrity: impactReason('integrity', metrics.integrity),
            availability: impactReason('availability', metrics.availability),
        },
    };
}
