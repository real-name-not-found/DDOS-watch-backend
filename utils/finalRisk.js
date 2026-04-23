// The dashboard now treats AbuseIPDB and whitelist status as the authoritative
// "final" risk decision, while ML remains an advisory signal shown separately.
const getFinalStatus = (abuseScore, isWhitelisted) => {
  const score = Number(abuseScore) || 0;

  if (isWhitelisted) {
    return 'WHITELISTED';
  }

  if (score >= 80) {
    return 'CRITICAL';
  }

  if (score >= 60) {
    return 'HIGH';
  }

  if (score >= 30) {
    return 'MODERATE';
  }

  return 'LOW';
};

// Keeps the backend API semantics aligned with what the frontend presents to the
// user so "final risk" means the same thing everywhere.
const buildRecommendation = (finalLabel) => {
  if (finalLabel === 'WHITELISTED') {
    return 'AbuseIPDB marks this IP as whitelisted. Treat the AI prediction as advisory and prefer the provider judgment for the final decision.';
  }

  if (finalLabel === 'CRITICAL') {
    return 'AbuseIPDB indicates severe abuse activity. Investigate immediately before allowing traffic.';
  }

  if (finalLabel === 'HIGH') {
    return 'AbuseIPDB indicates elevated abuse activity. Review the provider evidence before blocking or rate limiting.';
  }

  if (finalLabel === 'MODERATE') {
    return 'AbuseIPDB shows moderate abuse activity. Keep monitoring and review additional context before taking action.';
  }

  return 'AbuseIPDB does not currently indicate severe abuse. Continue monitoring this IP normally.';
};

// Final risk is intentionally AbuseIPDB-first so backend payloads, cached rows,
// exports, and the UI all describe the same "final" score and label.
const buildFinalRisk = ({ abuseScore, isWhitelisted }) => {
  const score = Number(abuseScore) || 0;
  const finalLabel = getFinalStatus(score, isWhitelisted);

  return {
    finalRiskScore: score,
    finalRiskLabel: finalLabel,
    finalRecommendation: buildRecommendation(finalLabel),
  };
};

module.exports = { buildFinalRisk };
