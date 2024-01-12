IP_COMMENT_TEMPLATE = """
The IP `{{ data.id }}` was found in VirusTotal.

**Analysis State:**

Harmless: {{ data.attributes.last_analysis_stats.harmless }}
Malicious: {{ data.attributes.last_analysis_stats.malicious }}
Suspicious: {{ data.attributes.last_analysis_stats.suspicious }}
Undetected: {{ data.attributes.last_analysis_stats.undetected }}
Timeout: {{ data.attributes.last_analysis_stats.timeout }}

**Community Votes:**
{{ data.attributes.total_votes.harmless }} harmless
{{ data.attributes.total_votes.malicious }} malcious
"""

FILE_REPORT_HASH_COMMENT_TEMPLATE = """
The file hash `{{ data.id }}` was found in VirusTotal.

**{{ data.attributes.last_analysis_stats.malicious }}** AV engines have identiiied this file as malicious.
"""

DOMAIN_REPORT_COMMENT_TEMPLATE = """
The file hash `{{ data.id }}` was found in VirusTotal.

**{{ data.attributes.last_analysis_stats.malicious }}** AV engines have identiiied this file as malicious.
"""
