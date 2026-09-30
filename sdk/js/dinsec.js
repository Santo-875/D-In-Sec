/**
 * sdk/js/dinsec.js — Official JavaScript / Node.js SDK for D-In-Sec M3 Sidecar.
 */

const crypto = require('crypto');

class DinSecClient {
    /**
     * @param {Object} options
     * @param {string} [options.baseUrl='http://127.0.0.1:5001']
     * @param {string} [options.apiKey='dev-service-key']
     * @param {string} [options.tenantId='default']
     */
    constructor(options = {}) {
        this.baseUrl = (options.baseUrl || 'http://127.0.0.1:5001').replace(/\/$/, '');
        this.apiKey = options.apiKey || 'dev-service-key';
        this.tenantId = options.tenantId || 'default';
    }

    _headers(custom = {}) {
        return {
            'X-API-Key': this.apiKey,
            'X-Tenant-ID': this.tenantId,
            'Content-Type': 'application/json',
            ...custom
        };
    }

    async _fetch(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = this._headers(options.headers);
        const res = await fetch(url, { ...options, headers });
        const data = await res.json().catch(() => ({}));
        return { status: res.status, data };
    }

    async isAlive() {
        try {
            const { status } = await this._fetch('/healthz');
            return status === 200;
        } catch (e) {
            return false;
        }
    }

    async isReady() {
        const { data } = await this._fetch('/readyz');
        return data;
    }

    /**
     * Ingest an event with client-side RSA signature.
     */
    async ingestEvent({ userId, leafId, maskedPii, realData, privateKeyPem, version = 1 }) {
        const maskedPiiHash = crypto.createHash('sha256').update(maskedPii, 'utf8').digest('hex');
        const realDataHash = crypto.createHash('sha256').update(realData, 'utf8').digest('hex');
        const timestamp = new Date().toISOString();
        const eventId = `evt_${crypto.randomBytes(6).toString('hex')}`;
        const nonce = crypto.randomBytes(16).toString('hex');

        const payload = {
            user_id: userId,
            leaf_id: leafId,
            event_id: eventId,
            nonce: nonce,
            version: version,
            masked_pii_hash: maskedPiiHash,
            real_data_hash: realDataHash,
            timestamp: timestamp
        };

        // Canonical JSON signing
        const sortedKeys = Object.keys(payload).sort();
        const canonical = JSON.stringify(payload, sortedKeys);
        const sign = crypto.createSign('SHA256');
        sign.update(canonical);
        sign.end();
        payload.signature_hex = sign.sign(privateKeyPem, 'hex');

        const { data } = await this._fetch('/v1/events', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        return data;
    }

    async classifyText(text) {
        const { data } = await this._fetch('/v1/events', {
            method: 'POST',
            body: JSON.stringify({ text })
        });
        return data;
    }

    async verifyAudit({ userId, leafId, maskedPiiHash, realDataHash }) {
        const { data } = await this._fetch('/audit/verify', {
            method: 'POST',
            body: JSON.stringify({
                user_id: userId,
                leaf_id: leafId,
                masked_pii_hash: maskedPiiHash,
                real_data_hash: realDataHash
            })
        });
        return data;
    }

    async fullVerify() {
        const { data } = await this._fetch('/v1/verify/full');
        return data;
    }

    async triggerAnchor() {
        const { data } = await this._fetch('/v1/admin/anchor', { method: 'POST' });
        return data;
    }

    async getAlerts(unresolvedOnly = false) {
        const q = unresolvedOnly ? '?unresolved=true' : '';
        const { data } = await this._fetch(`/v1/alerts${q}`);
        return data.alerts || [];
    }

    async exportCertinBundle(fromDate = '', toDate = '') {
        const params = new URLSearchParams();
        if (fromDate) params.set('from', fromDate);
        if (toDate) params.set('to', toDate);
        const qs = params.toString() ? `?${params.toString()}` : '';
        const { data } = await this._fetch(`/v1/export/certin${qs}`);
        return data;
    }
}

module.exports = { DinSecClient };
