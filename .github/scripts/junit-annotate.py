"""Turn PHPUnit JUnit XML failures into GitHub annotations (visible without opening logs)."""
import sys
import xml.etree.ElementTree as ET

try:
    root = ET.parse(sys.argv[1]).getroot()
except (OSError, ET.ParseError) as e:
    print(f"::warning::no junit report ({e})")
    sys.exit(0)

for case in root.iter("testcase"):
    for tag in ("failure", "error"):
        for node in case.findall(tag):
            text = (node.text or node.get("message") or "").strip().replace("\r", "")
            msg = "%0A".join(text.splitlines()[:25])[:3500]
            print(f"::error title={case.get('class', '')}::{case.get('name')}%0A{msg}")
