"""
False positive test suite: legitimate content must NOT be flagged.

Every test here is a real-world text or file pattern that stegOFF
should accept as clean. Any finding is a false positive that needs fixing.
"""

import io
import json
import tempfile
from pathlib import Path

import pytest
import numpy as np
from PIL import Image

from stegoff.orchestrator import scan, scan_text, scan_file


# ===========================================================================
# ENGLISH PROSE
# ===========================================================================

class TestCleanEnglishProse:

    @pytest.mark.parametrize("text", [
        "The quick brown fox jumps over the lazy dog.",
        "Meeting at 3pm in Conference Room B. Bring the Q3 report.",
        "Dear Customer,\n\nThank you for your purchase.\nOrder #12345 ships tomorrow.\n\nBest regards,\nSupport Team",
        "The annual shareholder meeting will be held on March 15th at the Hilton downtown. Parking is available in the garage on 5th Street. Please bring valid photo ID.",
        "I've been thinking about the proposal and I think we should move forward. The numbers look good and the timeline is realistic. Let's discuss on Monday.",
        "BREAKING: Scientists discover high concentrations of microplastics in deep ocean trenches. Research published in Nature suggests contamination extends to previously untested depths.",
        "Recipe: Preheat oven to 375F. Mix 2 cups flour, 1 cup sugar, 3 eggs. Bake 25 minutes until golden brown. Let cool on wire rack.",
        "The patient presented with mild symptoms including headache and fatigue. Vitals were within normal range. Recommended rest and follow-up in one week.",
    ])
    def test_english_prose(self, text):
        report = scan_text(text)
        assert report.clean, f"FP on English: {[f.description for f in report.findings]}"


# ===========================================================================
# INTERNATIONAL TEXT (6 languages)
# ===========================================================================

class TestCleanInternational:

    @pytest.mark.parametrize("label,text", [
        ("Japanese", "日本語のテスト文章です。東京は美しい都市です。桜の季節は特に素晴らしい。"),
        ("Chinese", "这是一个测试文档。北京是中国的首都。今天天气很好。"),
        ("Arabic", "مرحبا بالعالم. هذا نص عربي عادي. الطقس جميل اليوم."),
        ("Russian", "Привет мир. Это обычный русский текст. Погода сегодня хорошая."),
        ("Korean", "한국어 텍스트입니다. 서울은 아름다운 도시입니다. 오늘 날씨가 좋습니다."),
        ("French", "Le café résumé était très intéressant. Nous étions surpris par les résultats."),
        ("German", "Die Konferenz findet am Freitag statt. Bitte bringen Sie Ihre Unterlagen mit."),
        ("Spanish", "El informe trimestral muestra un crecimiento significativo en todas las regiones."),
        ("Hindi", "यह एक परीक्षण दस्तावेज़ है। मुंबई भारत का सबसे बड़ा शहर है।"),
        ("Thai", "นี่คือข้อความทดสอบ กรุงเทพมหานครเป็นเมืองหลวงของประเทศไทย"),
    ])
    def test_international_text(self, label, text):
        report = scan_text(text)
        assert report.clean, f"FP on {label}: {[f.description for f in report.findings]}"


# ===========================================================================
# TECHNICAL / CODE STRINGS
# ===========================================================================

class TestCleanTechnical:

    @pytest.mark.parametrize("text", [
        "SELECT u.id, u.name FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 ORDER BY o.created_at DESC LIMIT 50;",
        "git commit -m 'fix: resolve null pointer in auth middleware'",
        "npm install --save-dev @types/node typescript eslint prettier",
        "const result = arr.filter(x => x > 0).map(x => x * 2).reduce((a, b) => a + b, 0);",
        "docker run -d --name postgres -e POSTGRES_PASSWORD=secret -p 5432:5432 postgres:16",
        "kubectl get pods -n production --selector=app=api-server -o wide",
        "curl -X POST https://api.example.com/v2/users -H 'Content-Type: application/json' -d '{\"name\": \"test\"}'",
        "ssh -i ~/.ssh/id_rsa -L 8080:localhost:3000 deploy@staging.example.com",
        "pip install numpy>=1.24 pandas scikit-learn torch transformers",
        "grep -rn 'TODO\\|FIXME' src/ --include='*.py' | wc -l",
    ])
    def test_technical_strings(self, text):
        report = scan_text(text)
        assert report.clean, f"FP on technical: {[f.description for f in report.findings]}"


# ===========================================================================
# EMOJI IN NATURAL CONTEXT
# ===========================================================================

class TestCleanEmoji:

    @pytest.mark.parametrize("text", [
        "Great job on the release! 🎉 The team did amazing work 💪",
        "Weather: ☀️ 75F | Tomorrow: 🌧️ 62F | Weekend: ⛅ 68F",
        "Happy birthday! 🎂🎈🎁 Hope you have an amazing day! 🥳",
        "Road trip playlist: 🎵 Country roads 🎶 Hotel California 🎵 Bohemian Rhapsody",
        "Dinner tonight: 🍕 or 🍔? Vote below! 👇",
        "Status update: ✅ Design review ✅ Code complete ⏳ Testing 📋 Deploy",
        "Good morning! ☕ Ready for another productive day 💻",
        "Family vacation photos 📸🏖️🌊🐚🌅 What a week!",
    ])
    def test_emoji_in_context(self, text):
        report = scan_text(text)
        assert report.clean, f"FP on emoji: {[f.description for f in report.findings]}"


# ===========================================================================
# URLs, AUTH HEADERS, COMMON PATTERNS
# ===========================================================================

class TestCleanCommonPatterns:

    @pytest.mark.parametrize("text", [
        "Check https://docs.python.org/3/library/pathlib.html for details",
        "Authorization: Basic dXNlcjpwYXNz",
        "Config at /etc/nginx/nginx.conf and /var/log/nginx/access.log",
        "Invoice #2024-0847: $1,234.56 due 2024-03-15",
        "Temperature: 72.4F (22.4C) | Humidity: 45% | Wind: 12mph NW",
        "Version 3.2.1-beta.4+build.2024.03.15",
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "UUID: 550e8400-e29b-41d4-a716-446655440000",
        "IBAN: DE89370400440532013000 | SWIFT: COBADEFFXXX",
        "Regex: ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
        "MAC: 00:1A:2B:3C:4D:5E | IP: 192.168.1.100 | Port: 8443",
    ])
    def test_common_patterns(self, text):
        report = scan_text(text)
        assert report.clean, f"FP on pattern: {[f.description for f in report.findings]}"


# ===========================================================================
# JSON — NORMAL CONFIGS AND API RESPONSES
# ===========================================================================

class TestCleanJSON:

    def test_package_json(self):
        data = {
            "name": "my-project", "version": "1.0.0",
            "dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"},
            "scripts": {"start": "node index.js", "test": "jest --coverage"},
        }
        report = scan_text(json.dumps(data, indent=2))
        assert report.clean

    def test_api_response(self):
        data = {
            "status": "ok", "data": {
                "users": [
                    {"id": 1, "name": "Alice", "email": "alice@example.com"},
                    {"id": 2, "name": "Bob", "email": "bob@example.com"},
                ],
                "total": 2, "page": 1,
            }
        }
        report = scan_text(json.dumps(data, indent=2))
        assert report.clean

    def test_sensor_data(self):
        """Legitimate numeric arrays (not byte-encoded payloads)."""
        data = {
            "sensor": "thermometer_3",
            "readings": [22.1, 22.3, 22.0, 21.9, 22.4, 22.2, 22.5, 22.1, 21.8, 22.3],
            "unit": "celsius",
        }
        report = scan_text(json.dumps(data, indent=2))
        assert report.clean

    def test_large_int_array(self):
        """Array of large numbers (not ASCII range)."""
        data = {"timestamps": [1710000000 + i * 3600 for i in range(20)]}
        report = scan_text(json.dumps(data))
        assert report.clean

    def test_data_uri(self):
        """Base64 in data URIs is legitimate."""
        text = '{"avatar": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQABNjN9GQA"}'
        report = scan_text(text)
        assert report.clean


# ===========================================================================
# CODE FILES (inline)
# ===========================================================================

class TestCleanCodeInline:

    def test_python(self):
        code = '''"""A normal Python module."""
import os
from pathlib import Path

# Configuration
DEFAULT_PORT = 8080
MAX_RETRIES = 3

def fibonacci(n: int) -> int:
    """Calculate nth Fibonacci number."""
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

if __name__ == "__main__":
    print(f"Fibonacci(10) = {fibonacci(10)}")
'''
        report = scan_text(code)
        assert report.clean, f"FP on Python: {[f.description for f in report.findings]}"

    def test_html(self):
        html = '''<!DOCTYPE html>
<html lang="en">
<head><title>Welcome</title>
<style>body { font-family: sans-serif; } .hidden { display: none; } .btn:hover { background: #0052a3; }</style>
</head>
<body>
<div class="container">
  <h1>Welcome</h1>
  <p>Normal page content.</p>
  <button class="btn" onclick="alert('Hello!')">Click</button>
  <div class="hidden" id="loading">Loading...</div>
</div>
</body></html>'''
        report = scan_text(html)
        assert report.clean, f"FP on HTML: {[f.description for f in report.findings]}"

    def test_sql(self):
        sql = '''CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_users_email ON users(email);
INSERT INTO users (email, name) VALUES ('alice@example.com', 'Alice');'''
        report = scan_text(sql)
        assert report.clean, f"FP on SQL: {[f.description for f in report.findings]}"

    def test_css(self):
        css = '''*, *::before, *::after { box-sizing: border-box; }
body { font-family: -apple-system, sans-serif; line-height: 1.6; color: #333; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
.btn { display: inline-block; padding: 0.5rem 1rem; border: none; border-radius: 4px; }
.btn-primary { background: #0066cc; color: white; }'''
        report = scan_text(css)
        assert report.clean, f"FP on CSS: {[f.description for f in report.findings]}"

    def test_yaml(self):
        yaml = '''# Docker Compose
version: "3.8"
services:
  web:
    build: .
    ports:
      - "8080:8080"
    environment:
      - NODE_ENV=production
  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:'''
        report = scan_text(yaml)
        assert report.clean, f"FP on YAML: {[f.description for f in report.findings]}"

    def test_shell(self):
        sh = '''#!/bin/bash
# Deploy script
set -euo pipefail
ENV="${1:-production}"
TAG=$(git describe --tags --always)
echo "Deploying $TAG to $ENV..."
docker build -t myapp:"$TAG" .
docker service update --image myapp:"$TAG" myapp-service
echo "Done"'''
        report = scan_text(sh)
        assert report.clean, f"FP on Shell: {[f.description for f in report.findings]}"

    def test_xml(self):
        xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!-- Application config -->
<config>
    <database><host>localhost</host><port>5432</port></database>
    <server><bind>0.0.0.0</bind><port>8080</port><workers>4</workers></server>
    <logging level="info"><file>/var/log/app.log</file></logging>
</config>'''
        report = scan_text(xml)
        assert report.clean, f"FP on XML: {[f.description for f in report.findings]}"

    def test_ini(self):
        ini = '''; Application Configuration
[general]
app_name = MyApplication
version = 2.1.0
debug = false

[database]
host = localhost
port = 5432
max_connections = 20

[logging]
level = info
file = /var/log/myapp.log'''
        report = scan_text(ini)
        assert report.clean, f"FP on INI: {[f.description for f in report.findings]}"


# ===========================================================================
# EDGE CASES
# ===========================================================================

class TestCleanEdgeCases:

    def test_empty_string(self):
        assert scan_text("").clean

    def test_single_character(self):
        assert scan_text("A").clean

    def test_only_numbers(self):
        assert scan_text("123456789").clean

    def test_only_whitespace(self):
        assert scan_text("   \n\n   \t\t   ").clean

    def test_very_long_word(self):
        assert scan_text("a" * 10000).clean

    def test_long_document(self):
        paragraphs = [
            "This is paragraph one of a normal document.",
            "The second paragraph discusses technical matters.",
            "In paragraph three we examine the quarterly results.",
            "The final paragraph summarizes key findings.",
        ]
        text = "\n\n".join(paragraphs * 25)
        assert scan_text(text).clean

    def test_mixed_language_document(self):
        """English with occasional French/Spanish phrases (common in business)."""
        text = "The team delivered an excellent résumé of the project. Our raison d'être is customer satisfaction. The café near the office serves great empanadas."
        report = scan_text(text)
        assert report.clean

    def test_korean_with_hangul(self):
        """Korean text naturally uses Hangul characters."""
        text = "안녕하세요. 오늘 날씨가 좋습니다. 서울에서 만나요. 감사합니다."
        assert scan_text(text).clean

    def test_math_notation(self):
        text = "The equation x + y = z holds for all positive integers. Given f(x) = 2x + 3, find f(5)."
        assert scan_text(text).clean

    def test_base64_in_context(self):
        """Short base64 in auth headers is normal."""
        text = "Set header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        assert scan_text(text).clean

    def test_markdown_with_code_blocks(self):
        md = '''# API Guide

Use the following endpoint:

```bash
curl -X POST https://api.example.com/data \\
  -H "Authorization: Bearer TOKEN"
```

The response returns JSON with `status` and `data` fields.
'''
        assert scan_text(md).clean


# ===========================================================================
# IMAGES (clean, programmatic)
# ===========================================================================

class TestCleanImages:

    def _make_gradient_png(self):
        """Natural-looking gradient image."""
        from scipy.ndimage import gaussian_filter
        img = np.zeros((200, 200, 3), dtype=np.float64)
        for y in range(200):
            for x in range(200):
                img[y, x] = [100 + 80*(1-y/200), 150 + 60*(1-y/200), 200 + 55*(1-y/200)] if y < 100 else [60+80*(y-100)/100, 100+40*(y-100)/100, 40+30*(y-100)/100]
        for c in range(3):
            img[:, :, c] = gaussian_filter(img[:, :, c], sigma=5.0)
        return Image.fromarray(img.astype(np.uint8))

    def test_clean_png_no_structural_findings(self):
        """Clean generated image should have no structural findings."""
        img = self._make_gradient_png()
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        report = scan(buf.getvalue())
        structural = [f for f in report.findings if f.method.value in (
            'trailing_data_after_eof', 'polyglot_file', 'embedded_file',
            'png_ancillary_chunks', 'metadata_exif_hiding',
        )]
        assert not structural, f"Structural FP on clean PNG: {structural}"

    def test_clean_jpeg_no_structural_findings(self):
        img = self._make_gradient_png()
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=85)
        report = scan(buf.getvalue())
        structural = [f for f in report.findings if f.method.value in (
            'trailing_data_after_eof', 'polyglot_file', 'embedded_file',
        )]
        assert not structural, f"Structural FP on clean JPEG: {structural}"


# ===========================================================================
# AUDIO (clean, programmatic)
# ===========================================================================

class TestCleanAudio:

    def test_clean_wav_no_structural_findings(self):
        """Synthetic chord WAV should have no structural findings."""
        import wave
        sample_rate = 44100
        t = np.linspace(0, 1.0, sample_rate, False)
        audio = np.zeros_like(t)
        for freq, amp in [(261.63, 0.4), (329.63, 0.3), (392.0, 0.25)]:
            audio += amp * np.sin(2 * np.pi * freq * t)
        envelope = np.ones_like(t)
        envelope[:int(0.05*sample_rate)] = np.linspace(0, 1, int(0.05*sample_rate))
        envelope[-int(0.2*sample_rate):] = np.linspace(1, 0, int(0.2*sample_rate))
        audio = (audio * envelope / np.max(np.abs(audio)) * 16000).astype(np.int16)

        buf = io.BytesIO()
        with wave.open(buf, 'w') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            wf.writeframes(audio.tobytes())

        report = scan(buf.getvalue())
        structural = [f for f in report.findings if f.method.value in (
            'trailing_data_after_eof', 'polyglot_file', 'embedded_file',
        )]
        assert not structural, f"Structural FP on clean WAV: {structural}"


# ===========================================================================
# FILES VIA scan_file (temp files)
# ===========================================================================

class TestCleanFileScan:

    @pytest.mark.parametrize("ext,content", [
        (".py", "import os\nprint('hello')\n"),
        (".js", "const x = 42;\nconsole.log(x);\n"),
        (".json", '{"name": "test", "version": "1.0"}\n'),
        (".html", "<html><body><p>Hello</p></body></html>\n"),
        (".xml", '<?xml version="1.0"?>\n<root><item>test</item></root>\n'),
        (".yaml", "name: test\nversion: 1.0\n"),
        (".sh", "#!/bin/bash\necho hello\n"),
        (".sql", "SELECT 1;\n"),
        (".css", "body { color: #333; }\n"),
        (".ini", "[main]\nkey = value\n"),
        (".md", "# Title\n\nSome text.\n"),
        (".csv", "name,age\nAlice,30\nBob,25\n"),
        (".txt", "Just a normal text file with nothing special.\n"),
    ])
    def test_clean_file(self, ext, content):
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode='w') as f:
            f.write(content)
            path = Path(f.name)
        try:
            report = scan_file(path)
            assert report.clean, f"FP on {ext}: {[f.description for f in report.findings]}"
        finally:
            path.unlink()


# ===========================================================================
# SUMMARY
# ===========================================================================

class TestFPSummary:
    """Marker to count total false positive tests."""
    def test_summary(self):
        """All false positive tests should pass. See output above."""
        pass
