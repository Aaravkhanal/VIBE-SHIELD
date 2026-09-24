function tokenSet(body = '') {
    return new Set(String(body).toLowerCase().replace(/<script[\s\S]*?<\/script>/g, ' ').replace(/[^a-z0-9]+/g, ' ').split(/\s+/).filter(token => token.length > 2).slice(0, 2000));
}

export function responseSimilarity(left = '', right = '') {
    const a = tokenSet(left);
    const b = tokenSet(right);
    if (a.size === 0 || b.size === 0) return 0;
    let common = 0;
    for (const token of a) if (b.has(token)) common++;
    return common / (a.size + b.size - common);
}

