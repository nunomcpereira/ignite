function createReviewDecisionStore() {
  const pending = new Map();

  function normalizeJobId(jobId) {
    const value = String(jobId || '').trim();
    if (!value) throw new Error('Job id is required.');
    if (/\0|\r|\n/.test(value)) throw new Error('Job id contains illegal control characters.');
    return value;
  }

  return {
    wait(jobId, timeoutMs = 5 * 60_000) {
      const safeJobId = normalizeJobId(jobId);
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          pending.delete(safeJobId);
          resolve({ proceed: false, reason: 'timeout' });
        }, timeoutMs);

        pending.set(safeJobId, {
          resolve: (decision) => {
            clearTimeout(timer);
            pending.delete(safeJobId);
            resolve(decision);
          },
        });
      });
    },

    resolve(jobId, decision) {
      const safeJobId = normalizeJobId(jobId);
      const entry = pending.get(safeJobId);
      if (!entry) return false;
      entry.resolve(decision);
      return true;
    },
  };
}

module.exports = { createReviewDecisionStore };
