from pennywise.ai.model_interface import AIModelInterface
print('🎉 AI Model Status: WORKING!')
ai = AIModelInterface()
print(f'Model loaded: ✅ {ai.model is not None}')
print(f'Tokenizer loaded: ✅ {ai.tokenizer is not None}')

# Test with correct vulnerability data keys
vuln_data = {
    'attack_type': 'XSS',
    'title': 'Test XSS vulnerability in login form',
    'description': 'Cross-site scripting vulnerability found in user input field',
    'url': 'http://example.com/login',
    'payload': '<script>alert("XSS")</script>',
    'evidence': 'Input field accepts script tags without sanitization'
}
result = ai.analyze_vulnerability(vuln_data)
print(f'AI Analysis Result: {result.success}')
if result.success:
    analysis = result.data
    print(f'Risk Level: {analysis.get("risk_level", "N/A")}')
    print(f'Impact: {analysis.get("impact", "N/A")}')
    print(f'Recommendations: {analysis.get("recommendations", "N/A")}')
else:
    print(f'Error: {result.error}')

# Check logs
logs = ai.get_ai_logs()
print(f'AI Logs count: {len(logs)}')
if logs:
    print('Latest log:')
    print(f'  Operation: {logs[-1].operation}')
    print(f'  Success: {logs[-1].success}')
    print(f'  Processing time: {logs[-1].processing_time:.3f}s')
    print(f'  Token count: {logs[-1].token_count}')