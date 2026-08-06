"""
COMPREHENSIVE DKIM SELECTOR DATABASE
===================================
300+ unique selectors covering every major email service provider

Organized by:
- Service-specific selectors (vendor names, known patterns)
- Sequential patterns (s1-s6, k1-k6, selector1-5, etc.)
- Date-based patterns (YYYYMM, YYYYMMDD for Google-style rotation)
- Generic/common naming conventions
"""

# ============================================================================
# SERVICE-SPECIFIC SELECTORS
# ============================================================================

# Google Workspace / Gmail (date-based rotation + named)
GOOGLE_SELECTORS = [
    'google', 'googlemail', 'gapps', 'ga1',
    # Known date-based selectors observed in the wild
    '20120113', '20161025', '20210112', '20221208', '20230601',
]

# Microsoft 365 / Exchange Online
MICROSOFT_SELECTORS = [
    'selector1', 'selector2', 'selector3', 'microsoft',
]

# Proofpoint
PROOFPOINT_SELECTORS = [
    'proofpoint', 'proofpoint1', 'proofpoint2', 'proofpoint3',
    'pp', 'pp1', 'pp02', 'pphosted',
]

# Mimecast
MIMECAST_SELECTORS = [
    'mimecast', 'mc', 'mc1', 'mc2', 'mc3',
    'mimecast20190719', 'mimecast20200619',
]

# Other email providers
OTHER_EMAIL_PROVIDERS = [
    'zoho', 'zohomail',
    'fastmail', 'fm1', 'fm2', 'fm3',
    'yahoo', 'ymail',
    'rackspace', 'mailtrust',
    'barracuda', 'bcuda',
    'messagelabs', 'symantec',
    'cisco', 'ironport',
    'fortinet', 'fortimail',
    'protonmail', 'yandex', 'office365',
    'googleapps',
    'dynect', 'mxvault', 'vzrelay',
    'emarsys', 'emarsys1', 'emarsys2', 'emarsys3',
    'responsys', 'sailthru', 'yousendit',
    'ellucian', 'autotask',
]

# Marketing Platforms
MARKETING_PLATFORMS = [
    # Mailchimp / Mandrill
    'k1', 'k2', 'k3', 'k4', 'k5', 'k6', 'mailchimp', 'mandrill', 'md',
    # HubSpot
    'hs1', 'hs2', 'hs3', 'hubspot',
    # Marketo / Adobe
    'marketo', 'mkto', 'mkto1', 'mkto2',
    # Constant Contact
    'constantcontact', 'cc', 'cc1', 'cc2',
    # Salesforce Marketing Cloud / ExactTarget
    'exacttarget', 'et', 'sfmc', 'sfmc1',
    # Pardot
    'pardot', 'pi', 'pardot1',
    # ActiveCampaign
    'activecampaign', 'ac', 'ac1', 'ac2',
    # Campaign Monitor
    'campaignmonitor', 'cm', 'cm1',
    # AWeber
    'aweber', 'aw',
    # GetResponse
    'getresponse', 'gr', 'gr1',
    # Klaviyo
    'klaviyo', 'kl', 'kl1', 'kl2',
    # Drip / ConvertKit
    'drip', 'convertkit', 'ck',
    # Mailjet
    'mailjet', 'mj', 'mj1',
    # Brevo (formerly Sendinblue)
    'sendinblue', 'brevo', 'sib', 'sib1',
    # Emma
    'emma', 'myemma',
    # Moosend / Mailerlite
    'moosend', 'mailerlite', 'ml',
    # Omnisend
    'omnisend',
]

# Transactional ESPs
TRANSACTIONAL_ESP = [
    # SendGrid
    'sendgrid', 'sg', 'sg1', 'sg2', 'em', 'em1', 'em2',
    's1', 's2', 's3', 's4', 's5', 's6',
    # Amazon SES
    'amazonses', 'ses', 'aws', 'ses1', 'ses2',
    # Mailgun
    'mailgun', 'mg', 'mg1', 'mg2',
    # SparkPost / MessageBird
    'sparkpost', 'sp', 'sp1', 'sp2', 'scph', 'scph0819', 'messagebird',
    # Postmark
    'postmark', 'pm', 'pm1', 'pm2',
    # Elastic Email
    'elasticemail', 'ee', 'ee1',
    # Socket Labs
    'socketlabs', 'smtpcom',
    # Omnivery / Mailkit
    'mailkit', 'mkt', 'omnivery', 'mk',
    # Other transactional
    'pepipost', 'dyn', 'twilio',
    'smtp2go', 'turbosmtp',
    'maileroo', 'resend',
    'smtpapi', 'smtpauth', 'smtpd', 'smtpcomcustomers',
    'sendmail', 'mailer',
    'pmta', 'postfix',
    'exim', 'exim4u',
    'mdaemon',
]

# CRM & Sales Platforms
CRM_PLATFORMS = [
    'salesforce', 'salesforce1', 'salesforce2', 'sf', 'sfdc', 'sf1', 'sf2',
    'dynamics', 'crm', 'crm1',
    'pipedrive', 'pd',
    'close', 'closeio',
    'outreach', 'salesloft',
    'yesware', 'yw',
    'mixmax',
    'reply', 'replyio', 'copper',
    'apollo', 'apollo1',
]

# Support Platforms
SUPPORT_PLATFORMS = [
    'zendesk', 'zendesk1', 'zendesk2', 'zd', 'zd1', 'zd2',
    'freshdesk', 'fd', 'fd1', 'freshworks',
    'helpscout', 'hs',
    'intercom', 'ic', 'ic1',
    'front', 'frontapp',
    'groove', 'kayako',
    'gorgias', 'desk',
    'jira', 'atlassian',
]

# E-commerce Platforms
ECOMMERCE_PLATFORMS = [
    'shopify', 'shops', 'myshopify',
    'woocommerce', 'woo', 'wordpress', 'wp',
    'bigcommerce', 'bc',
    'magento', 'mg',
    'squarespace', 'sqsp',
    'wix', 'prestashop', 'opencart',
    'stripe', 'square',
]

# Notification & Messaging
NOTIFICATION_PLATFORMS = [
    'customer', 'customerio', 'cio',
    'iterable', 'it',
    'braze', 'appboy',
    'onesignal', 'os',
    'firebase', 'fcm', 'airship',
    'pushover', 'twilio',
]

# Webinar, Events, Survey, Scheduling, HR, LMS
OTHER_PLATFORMS = [
    # Webinar & Events
    'zoom', 'zm', 'gotowebinar', 'gtw', 'webex', 'wx',
    'demio', 'livestorm', 'eventbrite', 'eb',
    # Survey
    'surveymonkey', 'sm', 'typeform', 'tf', 'qualtrics', 'qt',
    # Scheduling
    'calendly', 'cal', 'acuity', 'doodle',
    # HR & Recruiting
    'greenhouse', 'gh', 'lever', 'lv', 'workable', 'bamboohr',
    'namely', 'gusto', 'workday', 'adp',
    # LMS
    'teachable', 'thinkific', 'kajabi', 'udemy',
]

# ============================================================================
# SEQUENTIAL PATTERNS
# Covers numbered selectors many services rotate through
# ============================================================================

def _generate_sequential_selectors():
    """Generate numbered selector patterns from external scan databases"""
    selectors = []
    # selector1-20 (Microsoft, custom)
    selectors += [f'selector{i}' for i in range(1, 21)]
    # s1-s20
    selectors += [f's{i}' for i in range(1, 21)]
    # k1-k20
    selectors += [f'k{i}' for i in range(1, 21)]
    # key1-20
    selectors += [f'key{i}' for i in range(1, 21)]
    # dkim1-20
    selectors += [f'dkim{i}' for i in range(1, 21)]
    # dk1-20
    selectors += [f'dk{i}' for i in range(1, 21)]
    # sel1-20
    selectors += [f'sel{i}' for i in range(1, 21)]
    # m1-20
    selectors += [f'm{i}' for i in range(1, 21)]
    # v1-5
    selectors += [f'v{i}' for i in range(1, 6)]
    # eb1-20 (ryancdotorg pattern)
    selectors += [f'eb{i}' for i in range(1, 21)]
    # my1-20 (ryancdotorg pattern)
    selectors += [f'my{i}' for i in range(1, 21)]
    # ls1-20 (ryancdotorg pattern)
    selectors += [f'ls{i}' for i in range(1, 21)]
    # sl1-20
    selectors += [f'sl{i}' for i in range(1, 21)]
    # rsa1-20 (ryancdotorg pattern)
    selectors += [f'rsa{i}' for i in range(1, 21)]
    # yesmail1-20
    selectors += [f'yesmail{i}' for i in range(1, 21)]
    # sig1-5
    selectors += [f'sig{i}' for i in range(1, 6)]
    # default1-5
    selectors += [f'default{i}' for i in range(1, 6)]
    # smtp1-5
    selectors += [f'smtp{i}' for i in range(1, 6)]
    # mail1-5
    selectors += [f'mail{i}' for i in range(1, 6)]
    # relay1-3
    selectors += [f'relay{i}' for i in range(1, 4)]
    # em1-5 (SendGrid CNAME style)
    selectors += [f'em{i}' for i in range(1, 6)]
    # server1-5
    selectors += [f'server{i}' for i in range(1, 6)]
    # dk01-20 (zero-padded, ryancdotorg)
    selectors += [f'dk{i:02d}' for i in range(1, 21)]
    # dkim01-20 (zero-padded)
    selectors += [f'dkim{i:02d}' for i in range(1, 21)]
    return selectors

SEQUENTIAL_SELECTORS = _generate_sequential_selectors()

# ============================================================================
# DATE-BASED PATTERNS
# Google rotates selectors with YYYYMMDD format
# Some providers use YYYYMM or just YYYY
# ============================================================================

def _generate_date_selectors():
    """Generate date-based selectors for 2018-2027"""
    selectors = []
    for year in range(2018, 2028):
        # YYYY only
        selectors.append(str(year))
        for month in range(1, 13):
            # YYYYMM
            selectors.append(f'{year}{month:02d}')
            # YYYYMMDD - 1st and 15th of each month (common rotation dates)
            selectors.append(f'{year}{month:02d}01')
            selectors.append(f'{year}{month:02d}15')
    return selectors

DATE_SELECTORS = _generate_date_selectors()

# ============================================================================
# GENERIC / COMMON SELECTORS
# ============================================================================

GENERIC_SELECTORS = [
    # Standard naming
    'default', 'mail', 'email', 'dkim',
    'key', 'dk', 'sig', 'signature',
    's', 'mx', 'server',
    'primary', 'secondary',
    'smtp', 'smtpout',
    'main', 'maindomain',
    'prod', 'production',
    'send', 'sender',
    'outbound', 'out',
    'relay', 'bounce',
    'notify', 'notification',
    'newsletter', 'marketing',
    'transactional', 'noreply', 'no-reply',
    'bulk', 'promo',
    'big-email',
    # From ryancdotorg/dkimscan
    'allselector', 'alpha', 'beta', 'gamma', 'delta',
    'auth', 'authsmtp',
    'bfi', 'ca', 'care', 'centralsmtp', 'class', 'corp',
    'dk20050327', 'dk2024', 'dkimmail', 'dkimrnt', 'dkrnt', 'dksel',
    'domain', 'domainkey', 'domk', 'duh',
    'ebmailerd', 'ei',
    'gears', 'global', 'gmmailerd',
    'hubris', 'id', 'iport', 'iweb',
    'lists', 'mail-dkim', 'mail-in', 'mailo', 'mailrelay',
    'mesmtp', 'mikd', 'mimi', 'mkt', 'monkey', 'msa',
    'neomailout', 'one', 'originating',
    'postfix.private', 'primus', 'private', 'proddkim', 'publickey', 'pvt',
    'qcdkim',
    'safe', 'sasl', 'scarlet', 'scooby',
    'selector', 'sharedpool', 'sitemail',
    'snowcrash', 'spop', 'spop1024', 'squaremail', 'stigmate',
    'test', 'testdk', 'testdkim', 'tilprivate',
    'wesmail', 'www', 'x', 'yibm',
    # From pythia2/dkim-api
    's1024', 's2048', '1k', '2k',
    'abr', 'admin', 'bm', 'contact', 'dc',
    'gd', 'hello', 'ic', 'info', 'is',
    'mailtcex', 'mo', 'ms', 'ms1',
    'm1', 'mx1', 'mx2', 'nc',
    'pic', 'postmaster',
    'rs', 'rc', 'secure', 'security',
    'service', 'services', 'server1', 'server2',
    'sign', 'sign1', 'sign2',
    'smtpd', 'strong', 'strong1', 'strong2', 'ss',
    'sl', 'vr', 'webmaster',
    # From Hellfire4959
    'Corporate', 'ED-DKIM',
]

# ============================================================================
# MASTER LIST
# ============================================================================

_ALL_SELECTORS = (
    GOOGLE_SELECTORS +
    MICROSOFT_SELECTORS +
    PROOFPOINT_SELECTORS +
    MIMECAST_SELECTORS +
    OTHER_EMAIL_PROVIDERS +
    MARKETING_PLATFORMS +
    TRANSACTIONAL_ESP +
    CRM_PLATFORMS +
    SUPPORT_PLATFORMS +
    ECOMMERCE_PLATFORMS +
    NOTIFICATION_PLATFORMS +
    OTHER_PLATFORMS +
    SEQUENTIAL_SELECTORS +
    DATE_SELECTORS +
    GENERIC_SELECTORS
)

# Remove duplicates while preserving order
seen = set()
COMPREHENSIVE_DKIM_SELECTORS = [
    x for x in _ALL_SELECTORS
    if not (x in seen or seen.add(x))
]

# ============================================================================
# SPF VENDOR MAP - Maps SPF includes to vendors and their DKIM selectors
# ============================================================================

COMPREHENSIVE_SPF_VENDOR_MAP = {
    # Google
    '_spf.google.com': {'vendor': 'Google Workspace', 'dkim_selectors': ['google', 'googlemail', 'gapps', 'ga1']},
    'aspmx.googlemail.com': {'vendor': 'Google Workspace', 'dkim_selectors': ['google', 'googlemail']},
    # Microsoft
    'spf.protection.outlook.com': {'vendor': 'Microsoft 365', 'dkim_selectors': ['selector1', 'selector2', 'selector3']},
    # Proofpoint
    '_spf.pphosted.com': {'vendor': 'Proofpoint', 'dkim_selectors': ['proofpoint', 'proofpoint1', 'pp', 'pphosted']},
    # Mimecast
    '_spf.mimecast.com': {'vendor': 'Mimecast', 'dkim_selectors': ['mimecast', 'mc', 'mc1', 'mc2']},
    # Mailchimp
    'servers.mcsv.net': {'vendor': 'Mailchimp', 'dkim_selectors': ['k1', 'k2', 'k3']},
    # SendGrid
    'sendgrid.net': {'vendor': 'SendGrid', 'dkim_selectors': ['s1', 's2', 'em', 'sendgrid']},
    # Amazon SES
    'amazonses.com': {'vendor': 'Amazon SES', 'dkim_selectors': ['ses', 'amazonses', 'ses1', 'ses2']},
    # Mailgun
    'mailgun.org': {'vendor': 'Mailgun', 'dkim_selectors': ['mg', 'mg1', 'mailgun']},
    # Mandrill
    'mandrillapp.com': {'vendor': 'Mandrill', 'dkim_selectors': ['mandrill', 'k1']},
    # SparkPost
    'sparkpostmail.com': {'vendor': 'SparkPost', 'dkim_selectors': ['sparkpost', 'scph', 'sp']},
    # Constant Contact
    'constantcontact.com': {'vendor': 'Constant Contact', 'dkim_selectors': ['k1', 'k2', 'constantcontact']},
    # HubSpot
    '_spf.hubspot.com': {'vendor': 'HubSpot', 'dkim_selectors': ['hs1', 'hs2', 'hubspot']},
    # Marketo
    '_spf.marketo.com': {'vendor': 'Marketo', 'dkim_selectors': ['marketo', 'mkto', 'mkto1']},
    # Zendesk
    'mail.zendesk.com': {'vendor': 'Zendesk', 'dkim_selectors': ['zendesk', 'zendesk1', 'zendesk2', 'zd']},
    # Postmark
    'spf.mtasv.net': {'vendor': 'Postmark', 'dkim_selectors': ['postmark', 'pm', 'pm1']},
    # Klaviyo
    'send.klaviyo.com': {'vendor': 'Klaviyo', 'dkim_selectors': ['klaviyo', 'kl', 'kl1']},
    # ActiveCampaign
    'emsd1.com': {'vendor': 'ActiveCampaign', 'dkim_selectors': ['activecampaign', 'ac', 'ac1']},
    # Brevo / Sendinblue
    'spf.sendinblue.com': {'vendor': 'Brevo', 'dkim_selectors': ['sendinblue', 'brevo', 'sib']},
    # Mailjet
    'spf.mailjet.com': {'vendor': 'Mailjet', 'dkim_selectors': ['mailjet', 'mj', 'mj1']},
    # Freshdesk
    'email.freshdesk.com': {'vendor': 'Freshdesk', 'dkim_selectors': ['freshdesk', 'fd', 'freshworks']},
    # Shopify
    'shops.shopify.com': {'vendor': 'Shopify', 'dkim_selectors': ['shopify', 'shops', 'myshopify']},
    # Intercom
    'intercom.io': {'vendor': 'Intercom', 'dkim_selectors': ['intercom', 'ic', 'ic1']},
    # Omnivery / Mailkit
    'spf.mailkit.eu': {'vendor': 'Omnivery/Mailkit', 'dkim_selectors': ['mailkit', 'mkt', 'omnivery', 'mk']},
    'mailkit.eu': {'vendor': 'Omnivery/Mailkit', 'dkim_selectors': ['mailkit', 'mkt', 'omnivery', 'mk']},
}

# ============================================================================
# STATS
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print(" COMPREHENSIVE DKIM SELECTOR DATABASE")
    print("=" * 70)
    print(f"\n Total Unique Selectors: {len(COMPREHENSIVE_DKIM_SELECTORS)}")
    print("\n By Category:")
    print(f"   Google:              {len(GOOGLE_SELECTORS)}")
    print(f"   Microsoft:           {len(MICROSOFT_SELECTORS)}")
    print(f"   Proofpoint:          {len(PROOFPOINT_SELECTORS)}")
    print(f"   Mimecast:            {len(MIMECAST_SELECTORS)}")
    print(f"   Other Providers:     {len(OTHER_EMAIL_PROVIDERS)}")
    print(f"   Marketing:           {len(MARKETING_PLATFORMS)}")
    print(f"   Transactional:       {len(TRANSACTIONAL_ESP)}")
    print(f"   CRM/Sales:           {len(CRM_PLATFORMS)}")
    print(f"   Support:             {len(SUPPORT_PLATFORMS)}")
    print(f"   E-commerce:          {len(ECOMMERCE_PLATFORMS)}")
    print(f"   Notifications:       {len(NOTIFICATION_PLATFORMS)}")
    print(f"   Other Platforms:     {len(OTHER_PLATFORMS)}")
    print(f"   Sequential:          {len(SEQUENTIAL_SELECTORS)}")
    print(f"   Date-based:          {len(DATE_SELECTORS)}")
    print(f"   Generic:             {len(GENERIC_SELECTORS)}")
    print(f"\n SPF Vendor Mappings:   {len(COMPREHENSIVE_SPF_VENDOR_MAP)}")
    print("=" * 70)
