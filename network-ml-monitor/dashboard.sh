#!/bin/bash
clear
echo "=== ML FIREWALL DASHBOARD ==="
echo "Updated: $(date)"
echo ""

# Get stats (with error handling)
API_COUNT=$(sqlite3 logs/traffic.db "SELECT COUNT(*) FROM api_logs WHERE timestamp > strftime('%s', 'now', '-5 minutes');" 2>/dev/null || echo "0")
IP_COUNT=$(sqlite3 logs/traffic.db "SELECT COUNT(DISTINCT ip) FROM api_logs WHERE timestamp > strftime('%s', 'now', '-1 hour');" 2>/dev/null || echo "0")
ALERT_COUNT=$(sqlite3 logs/traffic.db "SELECT COUNT(*) FROM security_alerts WHERE timestamp > strftime('%s', 'now', '-24 hours');" 2>/dev/null || echo "0")

echo "📊 TRAFFIC RATE:"
echo "Requests/min (last 5m): $((API_COUNT / 5))"
echo "Unique IPs (last hour): $IP_COUNT"

echo ""
echo "🚨 THREAT DETECTION:"
echo "Total Alerts (24h): $ALERT_COUNT"
echo "Bots Detected: $(sqlite3 logs/traffic.db \"SELECT COUNT(*) FROM security_alerts WHERE is_bot=1 AND timestamp > strftime('%s', 'now', '-24 hours');\" 2>/dev/null || echo '0')"

echo ""
echo "📈 TOP 5 THREATS (Last Hour):"
sqlite3 logs/traffic.db "SELECT ip, risk_score, action FROM security_alerts WHERE timestamp > strftime('%s', 'now', '-1 hour') ORDER BY risk_score DESC LIMIT 5;" 2>/dev/null || echo "No threats"

echo ""
echo "📝 RECENT ACTIVITY:"
sqlite3 logs/traffic.db "SELECT ip, endpoint, timestamp FROM api_logs ORDER BY timestamp DESC LIMIT 5;" 2>/dev/null || echo "No data"
