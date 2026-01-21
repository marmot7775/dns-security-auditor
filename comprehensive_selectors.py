"""
COMPREHENSIVE DKIM SELECTOR DATABASE
===================================
220+ unique selectors covering every major email service provider

Based on 10+ years of consulting experience + vendor documentation
"""

# Email Providers (17 selectors)
EMAIL_PROVIDERS = [
    'google', 'googlemail', 'gapps',
    'selector1', 'selector2', 'microsoft',
    'proofpoint', 'pp', 'pphosted',
    'mimecast', 'mc', 'mc1', 'mc2',
    'zoho', 'zohomail', 'fastmail', 'yahoo',
]

# Marketing Platforms (38 selectors)
MARKETING_PLATFORMS = [
    'k1', 'k2', 'k3', 'mailchimp',
    'hs1', 'hs2', 'hubspot',
    'marketo', 'mkto', 'mkto1',
    'constantcontact', 'cc', 'cc1',
    'exacttarget', 'et', 'sfmc',
    'pardot', 'pi',
    'activecampaign', 'ac', 'ac1',
    'campaignmonitor', 'cm',
    'aweber', 'aw',
    'getresponse', 'gr',
    'klaviyo', 'kl',
    'drip', 'convertkit',
    'mailjet', 'mj',
    'sendinblue', 'brevo', 'sib',
    'emma', 'myemma',
]

# Transactional ESPs (28 selectors)
TRANSACTIONAL_ESP = [
    'sendgrid', 'sg', 'em', 's1', 's2',
    'amazonses', 'ses', 'aws',
    'mailgun', 'mg', 'mg1',
    'mandrill', 'md',
    'sparkpost', 'sp', 'scph',
    'postmark', 'pm', 'pm1',
    'elasticemail', 'ee',
    'socketlabs', 'smtp', 'smtpcom',
    'pepipost', 'dyn', 'twilio',
]

# CRM & Sales (18 selectors)
CRM_PLATFORMS = [
    'salesforce', 'sf', 'sfdc',
    'dynamics', 'crm',
    'pipedrive', 'pd',
    'close', 'closeio',
    'outreach', 'salesloft',
    'yesware', 'yw',
    'mixmax', 'mx',
    'reply', 'replyio', 'copper',
]

# Support Platforms (17 selectors)
SUPPORT_PLATFORMS = [
    'zendesk', 'zendesk1', 'zendesk2', 'zd',
    'freshdesk', 'fd',
    'helpscout', 'hs',
    'intercom', 'ic',
    'front', 'frontapp',
    'groove', 'kayako',
    'gorgias', 'desk', 'zoho',
]

# E-commerce (16 selectors)
ECOMMERCE_PLATFORMS = [
    'shopify', 'shops', 'myshopify',
    'woocommerce', 'woo', 'wordpress', 'wp',
    'bigcommerce', 'bc',
    'magento', 'mg',
    'squarespace', 'sqsp',
    'wix', 'prestashop', 'opencart',
]

# Notification & Messaging (12 selectors)
NOTIFICATION_PLATFORMS = [
    'customer', 'customerio', 'cio',
    'iterable', 'it',
    'braze', 'appboy',
    'onesignal', 'os',
    'firebase', 'fcm', 'airship',
]

# Webinar & Events (10 selectors)
WEBINAR_PLATFORMS = [
    'zoom', 'zm',
    'gotowebinar', 'gtw',
    'webex', 'wx',
    'demio', 'livestorm',
    'eventbrite', 'eb',
]

# Survey Tools (8 selectors)
SURVEY_PLATFORMS = [
    'surveymonkey', 'sm',
    'typeform', 'tf',
    'googleforms', 'gf',
    'qualtrics', 'qt',
]

# Scheduling (6 selectors)
SCHEDULING_PLATFORMS = [
    'calendly', 'cal',
    'acuity', 'ac',
    'simplybook', 'doodle',
]

# HR & Recruiting (10 selectors)
HR_PLATFORMS = [
    'greenhouse', 'gh',
    'lever', 'lv',
    'workable', 'bamboohr',
    'namely', 'gusto',
    'workday', 'adp',
]

# Learning Management (7 selectors)
LMS_PLATFORMS = [
    'teachable', 'tc',
    'thinkific', 'th',
    'kajabi', 'kj',
    'udemy',
]

# Generic/Common (40+ selectors)
GENERIC_SELECTORS = [
    'default', 'mail', 'email', 'dkim',
    'key', 'key1', 'key2', 'key3',
    'dk', 'sig', 'signature',
    's', 's1', 's2', 's3',
    'mx', 'server', 'primary', 'secondary',
    'dkim1', 'dkim2', 'dkim3',
    'default1', 'default2',
    'sig1', 'sig2',
    '2024', '2025', '2026',
    'big-email',  # Custom example
    'smtp1', 'smtp2',
    'maindomain', 'main',
    'prod', 'production',
    'send', 'sender',
    'outbound', 'out',
    'relay', 'relay1',
]

# ============================================================================
# MASTER LIST
# ============================================================================

COMPREHENSIVE_DKIM_SELECTORS = (
    EMAIL_PROVIDERS +
    MARKETING_PLATFORMS +
    TRANSACTIONAL_ESP +
    CRM_PLATFORMS +
    SUPPORT_PLATFORMS +
    ECOMMERCE_PLATFORMS +
    NOTIFICATION_PLATFORMS +
    WEBINAR_PLATFORMS +
    SURVEY_PLATFORMS +
    SCHEDULING_PLATFORMS +
    HR_PLATFORMS +
    LMS_PLATFORMS +
    GENERIC_SELECTORS
)

# Remove duplicates while preserving order
seen = set()
COMPREHENSIVE_DKIM_SELECTORS = [
    x for x in COMPREHENSIVE_DKIM_SELECTORS 
    if not (x in seen or seen.add(x))
]

# ============================================================================
# STATS
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print(" COMPREHENSIVE DKIM SELECTOR DATABASE")
    print("=" * 70)
    print(f"\n Total Unique Selectors: {len(COMPREHENSIVE_DKIM_SELECTORS)}")
    print(f"\n By Category:")
    print(f"   📧 Email Providers:        {len(EMAIL_PROVIDERS)}")
    print(f"   📢 Marketing Platforms:    {len(MARKETING_PLATFORMS)}")
    print(f"   🔔 Transactional ESPs:     {len(TRANSACTIONAL_ESP)}")
    print(f"   💼 CRM & Sales:            {len(CRM_PLATFORMS)}")
    print(f"   💬 Support Platforms:      {len(SUPPORT_PLATFORMS)}")
    print(f"   🛒 E-commerce:             {len(ECOMMERCE_PLATFORMS)}")
    print(f"   🔔 Notifications:          {len(NOTIFICATION_PLATFORMS)}")
    print(f"   🎥 Webinars/Events:        {len(WEBINAR_PLATFORMS)}")
    print(f"   📝 Surveys:                {len(SURVEY_PLATFORMS)}")
    print(f"   📅 Scheduling:             {len(SCHEDULING_PLATFORMS)}")
    print(f"   👥 HR/Recruiting:          {len(HR_PLATFORMS)}")
    print(f"   🎓 LMS:                    {len(LMS_PLATFORMS)}")
    print(f"   ⭐ Generic/Common:         {len(GENERIC_SELECTORS)}")
    print(f"\n" + "=" * 70)
    print(" WITH SPF INTELLIGENCE:")
    print("=" * 70)
    print(" ✓ Relevant selectors tested FIRST (from SPF)")
    print(" ✓ Remaining selectors tested AFTER")
    print(" ✓ Large list = Better coverage, NO speed penalty")
    print(" ✓ Example: Google + Mailchimp = ~6 tests instead of 220+")
    print("=" * 70)

# ============================================================================
# SPF VENDOR MAP - Maps SPF includes to vendors and their DKIM selectors
# ============================================================================

COMPREHENSIVE_SPF_VENDOR_MAP = {
    '_spf.google.com': {'vendor': 'Google Workspace', 'dkim_selectors': ['google', 'googlemail', 'gapps']},
    'aspmx.googlemail.com': {'vendor': 'Google Workspace', 'dkim_selectors': ['google', 'googlemail']},
    'spf.protection.outlook.com': {'vendor': 'Microsoft 365', 'dkim_selectors': ['selector1', 'selector2']},
    '_spf.pphosted.com': {'vendor': 'Proofpoint', 'dkim_selectors': ['proofpoint', 'pp', 'pphosted']},
    '_spf.mimecast.com': {'vendor': 'Mimecast', 'dkim_selectors': ['mimecast', 'mc', 'mc1']},
    'servers.mcsv.net': {'vendor': 'Mailchimp', 'dkim_selectors': ['k1', 'k2', 'k3']},
    'sendgrid.net': {'vendor': 'SendGrid', 'dkim_selectors': ['s1', 's2', 'sendgrid']},
    'amazonses.com': {'vendor': 'Amazon SES', 'dkim_selectors': ['ses', 'amazonses']},
    'mailgun.org': {'vendor': 'Mailgun', 'dkim_selectors': ['mg', 'mailgun']},
    '_spf.hubspot.com': {'vendor': 'HubSpot', 'dkim_selectors': ['hs1', 'hs2', 'hubspot']},
    '_spf.marketo.com': {'vendor': 'Marketo', 'dkim_selectors': ['marketo', 'mkto']},
    'mail.zendesk.com': {'vendor': 'Zendesk', 'dkim_selectors': ['zendesk', 'zd']},
}

