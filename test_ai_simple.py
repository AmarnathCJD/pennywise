from pennywise.ai.model_interface import AIModelInterface
import torch

print('🎉 AI Model Status: WORKING!')
ai = AIModelInterface()
print(f'Model loaded: ✅ {ai.model is not None}')
print(f'Tokenizer loaded: ✅ {ai.tokenizer is not None}')

# Test with correct vulnerability data keys but shorter
vuln_data = {
    'attack_type': 'XSS',
    'title': 'Test XSS',
    'description': 'XSS found',
    'url': 'http://example.com',
    'payload': '<script>alert(1)</script>',
    'evidence': 'No sanitization'
}

print('Testing vulnerability analysis...')
result = ai.analyze_vulnerability(vuln_data)
print(f'AI Analysis Result: {result.success}')
if not result.success:
    print(f'Error: {result.error}')
    if hasattr(result, 'raw_response') and result.raw_response:
        print(f'Raw response (first 1000 chars): {result.raw_response[:1000]}')

# Check logs
logs = ai.get_ai_logs()
print(f'AI Logs count: {len(logs)}')