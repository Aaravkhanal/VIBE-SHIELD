import { responseSimilarity } from '../utils/response-similarity.js';

function median(values) {
    const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
    if (sorted.length === 0) return null;
    const middle = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function medianAbsoluteDeviation(values) {
    const center = median(values);
    return center === null ? null : median(values.map(value => Math.abs(value - center)));
}

function bodyStructure(body = '', contentType = '') {
    if (/json/i.test(contentType) || /^[\s]*[\[{]/.test(body)) {
        try {
            const paths = [];
            const walk = (value, prefix = '$', depth = 0) => {
                if (depth > 5) return;
                if (Array.isArray(value)) {
                    paths.push(`${prefix}[]`);
                    for (const item of value.slice(0, 3)) walk(item, `${prefix}[]`, depth + 1);
                } else if (value && typeof value === 'object') {
                    for (const key of Object.keys(value).sort().slice(0, 100)) {
                        paths.push(`${prefix}.${key}`);
                        walk(value[key], `${prefix}.${key}`, depth + 1);
                    }
                } else {
                    paths.push(`${prefix}:${typeof value}`);
                }
            };
            walk(JSON.parse(body));
            return { type: 'json', signature: [...new Set(paths)].sort().join('|') };
        } catch { /* fall through */ }
    }

    if (/<[a-z][\s\S]*>/i.test(body)) {
        const tags = {};
        for (const match of body.matchAll(/<([a-z][\w-]*)\b/gi)) tags[match[1].toLowerCase()] = (tags[match[1].toLowerCase()] || 0) + 1;
        return { type: 'html', signature: Object.entries(tags).sort().map(([tag, count]) => `${tag}:${count}`).join('|') };
    }

    const lines = String(body).split(/\r?\n/).filter(Boolean).length;
    return { type: 'text', signature: `lines:${lines}|bucket:${Math.round(String(body).length / 100)}` };
}

function cookieNames(headers = {}) {
    const value = headers['set-cookie'] || headers['Set-Cookie'] || '';
    return String(value).split(/,(?=\s*[^;,=]+=[^;,]+)/).map(item => item.split(';')[0].split('=')[0].trim()).filter(Boolean).sort();
}

function normalizeSnapshot(raw = {}) {
    const headers = raw.headers instanceof Headers ? Object.fromEntries(raw.headers.entries()) : { ...(raw.headers || {}) };
    const body = String(raw.body ?? raw.html ?? '').slice(0, 1000000);
    const contentType = raw.contentType || headers['content-type'] || headers['Content-Type'] || '';
    return {
        status: Number.isFinite(raw.status) ? raw.status : null,
        body,
        contentType,
        structure: raw.structure || bodyStructure(body, contentType),
        durationMs: Number.isFinite(raw.durationMs) ? raw.durationMs : null,
        finalUrl: raw.finalUrl || raw.url || null,
        location: raw.location || headers.location || headers.Location || null,
        redirected: Boolean(raw.redirected),
        cookieNames: raw.cookieNames || cookieNames(headers),
        dom: raw.dom || null,
        headers,
        error: raw.error || null,
    };
}

function domSimilarity(left, right) {
    if (!left && !right) return 1;
    if (!left || !right) return 0;
    return responseSimilarity(JSON.stringify(left), JSON.stringify(right));
}

function compare(left, right) {
    if (!left || !right) return { score: 1, unavailable: true };
    const bodySim = left.body.length === 0 && right.body.length === 0 ? 1 : responseSimilarity(left.body, right.body);
    const structureSame = left.structure?.type === right.structure?.type && left.structure?.signature === right.structure?.signature;
    const statusChanged = left.status !== right.status;
    const redirectChanged = left.location !== right.location || left.finalUrl !== right.finalUrl || left.redirected !== right.redirected;
    const cookiesChanged = JSON.stringify(left.cookieNames) !== JSON.stringify(right.cookieNames);
    const domSim = domSimilarity(left.dom, right.dom);
    let score = 0;
    if (statusChanged) score += 0.3;
    score += (1 - bodySim) * 0.3;
    if (!structureSame) score += 0.15;
    if (redirectChanged) score += 0.2;
    if (cookiesChanged) score += 0.1;
    score += (1 - domSim) * 0.15;
    return {
        score: Number(Math.min(score, 1).toFixed(3)),
        statusChanged,
        bodySimilarity: Number(bodySim.toFixed(3)),
        structureSame,
        redirectChanged,
        cookiesChanged,
        domSimilarity: Number(domSim.toFixed(3)),
        timingDeltaMs: left.durationMs === null || right.durationMs === null ? null : right.durationMs - left.durationMs,
    };
}

function aggregate(samples) {
    const usable = samples.filter(sample => !sample.error);
    const representative = usable[0] || samples[0] || null;
    const durations = usable.map(sample => sample.durationMs).filter(Number.isFinite);
    const repeatComparisons = usable.slice(1).map(sample => compare(representative, sample));
    // A consistently unavailable endpoint is still a stable observation. This
    // matters for controls such as an intentionally unroutable SSRF canary:
    // repeated connection failures should not be mistaken for network noise.
    const errors = samples.filter(sample => sample.error).map(sample => sample.error);
    const stableErrors = samples.length >= 2 && usable.length === 0 && errors.length === samples.length && new Set(errors).size === 1;
    const stable = stableErrors || (usable.length >= 2 && repeatComparisons.every(item =>
        item.statusChanged === false && item.redirectChanged === false && item.structureSame !== false && item.bodySimilarity >= 0.8
    ));
    return {
        representative,
        sampleCount: samples.length,
        successCount: usable.length,
        medianDurationMs: median(durations),
        timingMadMs: medianAbsoluteDeviation(durations),
        stable,
        repeatComparisons,
    };
}

export class DifferentialEngine {
    constructor({ repetitions = 2, timeoutMs = 10000, logger = null, coverageTracker = null } = {}) {
        this.repetitions = Math.max(2, repetitions);
        this.timeoutMs = timeoutMs;
        this.logger = logger;
        this.coverageTracker = coverageTracker;
    }

    async run({ baseline, control, payload, execute = null, signal = null, repetitions = this.repetitions, transform = null }) {
        this.coverageTracker?.mutation(baseline, payload);
        const variants = { baseline, control, payload };
        const samples = { baseline: [], control: [], payload: [] };
        const runner = execute || ((request) => this.fetch(request));

        for (let attempt = 0; attempt < Math.max(2, repetitions); attempt++) {
            for (const name of ['baseline', 'control', 'payload']) {
                try {
                    const raw = normalizeSnapshot(await runner(variants[name], { variant: name, attempt }));
                    samples[name].push(transform ? normalizeSnapshot(transform(raw, { variant: name, attempt })) : raw);
                } catch (error) {
                    samples[name].push(normalizeSnapshot({ error: error.message }));
                }
            }
        }

        const aggregates = Object.fromEntries(Object.entries(samples).map(([name, values]) => [name, aggregate(values)]));
        const comparisons = {
            baselineControl: compare(aggregates.baseline.representative, aggregates.control.representative),
            baselinePayload: compare(aggregates.baseline.representative, aggregates.payload.representative),
            controlPayload: compare(aggregates.control.representative, aggregates.payload.representative),
        };

        const signalResults = signal ? Object.fromEntries(Object.entries(samples).map(([name, values]) => [name, values.map(value => signal(value, name))])) : null;
        const payloadSignalOnly = Boolean(signalResults &&
            signalResults.payload.length >= 2 && signalResults.payload.every(Boolean) &&
            signalResults.baseline.every(value => !value) && signalResults.control.every(value => !value));
        const comparisonFloor = comparisons.baselineControl.score + 0.12;
        const uniqueDifferential = comparisons.controlPayload.score >= Math.max(0.18, comparisonFloor) &&
            comparisons.baselinePayload.score >= Math.max(0.18, comparisonFloor);

        const timing = this._timingAnalysis(aggregates);
        const variantsStable = Object.values(aggregates).every(item => item.stable);
        const payloadUnique = payloadSignalOnly || uniqueDifferential || timing.payloadSpecific;

        return {
            requests: variants,
            samples,
            aggregates,
            comparisons,
            timing,
            signalResults,
            payloadSignalOnly,
            uniqueDifferential,
            payloadUnique,
            variantsStable,
            confirmed: variantsStable && payloadUnique,
            evidence: this.summarize({ aggregates, comparisons, timing, payloadSignalOnly, uniqueDifferential, variantsStable, payloadUnique }),
        };
    }

    async fetch(request) {
        const started = performance.now();
        try {
            const response = await fetch(request.url, {
                method: request.method || 'GET',
                headers: request.headers,
                body: request.body,
                redirect: request.redirect || 'follow',
                signal: AbortSignal.timeout(request.timeoutMs || this.timeoutMs),
            });
            const body = await response.text();
            this.coverageTracker?.apiTested(request.url, request.method || 'GET', response.status);
            this.coverageTracker?.response(request.url, response.status, Object.fromEntries(response.headers.entries()), body);
            return normalizeSnapshot({
                status: response.status,
                body,
                headers: response.headers,
                contentType: response.headers.get('content-type') || '',
                durationMs: performance.now() - started,
                finalUrl: response.url,
                location: response.headers.get('location'),
                redirected: response.redirected,
            });
        } catch (error) {
            return normalizeSnapshot({ durationMs: performance.now() - started, error: error.message });
        }
    }

    _timingAnalysis(aggregates) {
        const baseline = aggregates.baseline.medianDurationMs;
        const control = aggregates.control.medianDurationMs;
        const payload = aggregates.payload.medianDurationMs;
        const noise = Math.max(aggregates.baseline.timingMadMs || 0, aggregates.control.timingMadMs || 0, 50);
        const reference = baseline === null || control === null ? null : Math.max(baseline, control);
        const deltaMs = reference === null || payload === null ? null : payload - reference;
        return {
            baselineMedianMs: baseline,
            controlMedianMs: control,
            payloadMedianMs: payload,
            noiseMadMs: noise,
            payloadDeltaMs: deltaMs,
            payloadSpecific: deltaMs !== null && deltaMs >= Math.max(750, noise * 6),
        };
    }

    summarize({ aggregates, comparisons, timing, payloadSignalOnly, uniqueDifferential, variantsStable, payloadUnique }) {
        const compact = aggregate => ({
            status: aggregate.representative?.status ?? null,
            bodyLength: aggregate.representative?.body.length ?? 0,
            structure: aggregate.representative?.structure || null,
            medianDurationMs: aggregate.medianDurationMs === null ? null : Math.round(aggregate.medianDurationMs),
            timingMadMs: aggregate.timingMadMs === null ? null : Math.round(aggregate.timingMadMs),
            finalUrl: aggregate.representative?.finalUrl || null,
            location: aggregate.representative?.location || null,
            cookieNames: aggregate.representative?.cookieNames || [],
            dom: aggregate.representative?.dom || null,
            repeatsStable: aggregate.stable,
            successfulRepeats: aggregate.successCount,
        });
        return {
            baseline: compact(aggregates.baseline),
            control: compact(aggregates.control),
            payload: compact(aggregates.payload),
            comparisons,
            timing: { ...timing, baselineMedianMs: Math.round(timing.baselineMedianMs || 0), controlMedianMs: Math.round(timing.controlMedianMs || 0), payloadMedianMs: Math.round(timing.payloadMedianMs || 0), noiseMadMs: Math.round(timing.noiseMadMs || 0), payloadDeltaMs: Math.round(timing.payloadDeltaMs || 0) },
            payloadSignalOnly,
            uniqueDifferential,
            variantsStable,
            payloadUnique,
        };
    }
}

export default DifferentialEngine;
