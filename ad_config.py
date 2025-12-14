"""
Ad Configuration System
Easy configuration for AdSense, Montag (PropellerAds), and other ad networks
"""

# ========================================
# AD NETWORK SCRIPTS
# ========================================

# Google AdSense
ADSENSE_ENABLED = False
ADSENSE_CLIENT_ID = "ca-pub-XXXXXXXXXXXXXXXX"  # Replace with your AdSense client ID
ADSENSE_SCRIPT = """
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={client_id}"
     crossorigin="anonymous"></script>
"""

# Montag (PropellerAds)
MONTAG_ENABLED = False
MONTAG_PROPERTY_ID = "XXXXXX"  # Replace with your Montag property ID
MONTAG_SCRIPT = """
<script>
    (function(s,u,z,p){s.src=u,s.setAttribute('data-zone',z),p.appendChild(s);})(document.createElement('script'),'https://inklinkor.com/tag.min.js',{property_id},document.head);
</script>
"""

# Custom Ad Network (Add your own)
CUSTOM_AD_ENABLED = False
CUSTOM_AD_SCRIPT = """
<!-- Add your custom ad network script here -->
"""

# ========================================
# AD PLACEMENTS
# ========================================

"""
Available positions:
- header_top: Above the page title
- header_bottom: Below the page title, before loading screen
- content_top: At the top of results (after loading screen)
- content_middle: In the middle of analysis sections
- content_bottom: At the bottom of results (before footer)
- sidebar_top: Top of sidebar (if layout changes)
- sidebar_bottom: Bottom of sidebar (if layout changes)
"""

AD_PLACEMENTS = {
    # Ad Placement 1 - Header Top Banner
    "header_top": {
        "enabled": False,
        "type": "adsense",  # Options: "adsense", "montag", "custom"
        "adsense_slot": "XXXXXXXXXX",  # AdSense ad slot ID
        "adsense_format": "auto",  # "auto", "horizontal", "vertical", "rectangle"
        "adsense_responsive": True,
        "montag_zone_id": "XXXXXX",  # Montag zone ID
        "custom_code": """
            <!-- Your custom ad code here -->
        """,
        "container_class": "ad-container-horizontal",  # CSS class for styling
    },

    # Ad Placement 2 - Below Header
    "header_bottom": {
        "enabled": False,
        "type": "adsense",
        "adsense_slot": "XXXXXXXXXX",
        "adsense_format": "horizontal",
        "adsense_responsive": True,
        "montag_zone_id": "XXXXXX",
        "custom_code": "",
        "container_class": "ad-container-horizontal",
    },

    # Ad Placement 3 - Content Top (After Results Load)
    "content_top": {
        "enabled": False,
        "type": "adsense",
        "adsense_slot": "XXXXXXXXXX",
        "adsense_format": "auto",
        "adsense_responsive": True,
        "montag_zone_id": "XXXXXX",
        "custom_code": "",
        "container_class": "ad-container-horizontal",
    },

    # Ad Placement 4 - Content Middle (Between Analysis Sections)
    "content_middle": {
        "enabled": False,
        "type": "montag",  # Using Montag for variety
        "adsense_slot": "XXXXXXXXXX",
        "adsense_format": "auto",
        "adsense_responsive": True,
        "montag_zone_id": "XXXXXX",
        "custom_code": "",
        "container_class": "ad-container-horizontal",
    },

    # Ad Placement 5 - Content Bottom (Before Footer)
    "content_bottom": {
        "enabled": False,
        "type": "adsense",
        "adsense_slot": "XXXXXXXXXX",
        "adsense_format": "auto",
        "adsense_responsive": True,
        "montag_zone_id": "XXXXXX",
        "custom_code": "",
        "container_class": "ad-container-horizontal",
    },

    # Ad Placement 6 - Sidebar Top (Future use)
    "sidebar_top": {
        "enabled": False,
        "type": "adsense",
        "adsense_slot": "XXXXXXXXXX",
        "adsense_format": "vertical",
        "adsense_responsive": True,
        "montag_zone_id": "XXXXXX",
        "custom_code": "",
        "container_class": "ad-container-vertical",
    },

    # Ad Placement 7 - Sidebar Bottom (Future use)
    "sidebar_bottom": {
        "enabled": False,
        "type": "montag",
        "adsense_slot": "XXXXXXXXXX",
        "adsense_format": "rectangle",
        "adsense_responsive": True,
        "montag_zone_id": "XXXXXX",
        "custom_code": "",
        "container_class": "ad-container-vertical",
    },
}

# ========================================
# AD GENERATION FUNCTIONS
# ========================================

def get_network_scripts():
    """Get all enabled ad network scripts to include in <head>"""
    scripts = []

    if ADSENSE_ENABLED:
        scripts.append(ADSENSE_SCRIPT.format(client_id=ADSENSE_CLIENT_ID))

    if MONTAG_ENABLED:
        scripts.append(MONTAG_SCRIPT.format(property_id=MONTAG_PROPERTY_ID))

    if CUSTOM_AD_ENABLED:
        scripts.append(CUSTOM_AD_SCRIPT)

    return '\n'.join(scripts)

def generate_adsense_ad(slot_id, format_type="auto", responsive=True):
    """Generate AdSense ad unit HTML"""
    if responsive:
        return f"""
        <ins class="adsbygoogle"
             style="display:block"
             data-ad-client="{ADSENSE_CLIENT_ID}"
             data-ad-slot="{slot_id}"
             data-ad-format="{format_type}"
             data-full-width-responsive="true"></ins>
        <script>
             (adsbygoogle = window.adsbygoogle || []).push({{}});
        </script>
        """
    else:
        return f"""
        <ins class="adsbygoogle"
             style="display:inline-block"
             data-ad-client="{ADSENSE_CLIENT_ID}"
             data-ad-slot="{slot_id}"></ins>
        <script>
             (adsbygoogle = window.adsbygoogle || []).push({{}});
        </script>
        """

def generate_montag_ad(zone_id):
    """Generate Montag (PropellerAds) ad unit HTML"""
    return f"""
    <div id="montag-{zone_id}"></div>
    <script>
        (function(d,z,s){{s.src='https://'+d+'/400/'+z;try{{(document.body||document.documentElement).appendChild(s)}}catch(e){{}}}})('{MONTAG_PROPERTY_ID}',{zone_id},document.createElement('script'));
    </script>
    """

def get_ad_placement(position):
    """Get ad HTML for a specific position"""
    if position not in AD_PLACEMENTS:
        return ""

    placement = AD_PLACEMENTS[position]

    if not placement["enabled"]:
        return ""

    ad_html = ""

    if placement["type"] == "adsense" and ADSENSE_ENABLED:
        ad_html = generate_adsense_ad(
            placement["adsense_slot"],
            placement["adsense_format"],
            placement["adsense_responsive"]
        )
    elif placement["type"] == "montag" and MONTAG_ENABLED:
        ad_html = generate_montag_ad(placement["montag_zone_id"])
    elif placement["type"] == "custom":
        ad_html = placement["custom_code"]

    if ad_html:
        return f"""
        <div class="ad-placement {placement['container_class']}" data-position="{position}">
            {ad_html}
        </div>
        """

    return ""

def get_all_ad_placements():
    """Get all enabled ad placements as a dictionary"""
    return {
        position: get_ad_placement(position)
        for position in AD_PLACEMENTS.keys()
    }

# ========================================
# CONFIGURATION INSTRUCTIONS
# ========================================

"""
HOW TO CONFIGURE ADS:

1. ENABLE AD NETWORKS:
   - Set ADSENSE_ENABLED = True
   - Set ADSENSE_CLIENT_ID = "ca-pub-XXXXXXXXXXXXXXXX"

   - Set MONTAG_ENABLED = True
   - Set MONTAG_PROPERTY_ID = "XXXXXX"

2. CONFIGURE AD PLACEMENTS:
   - Go to AD_PLACEMENTS dictionary
   - For each position, set "enabled": True
   - Choose "type": "adsense", "montag", or "custom"
   - Fill in the corresponding IDs:
     * adsense_slot: Your AdSense ad unit ID
     * montag_zone_id: Your Montag zone ID
     * custom_code: Your custom ad HTML

3. EXAMPLE CONFIGURATION:

AD_PLACEMENTS = {
    "header_top": {
        "enabled": True,  # Enable this ad
        "type": "adsense",
        "adsense_slot": "1234567890",
        "adsense_format": "horizontal",
        "adsense_responsive": True,
    },
    "content_middle": {
        "enabled": True,
        "type": "montag",
        "montag_zone_id": "5678901",
    },
}

4. AD FORMATS (AdSense):
   - "auto": Automatic sizing
   - "horizontal": Wide banner (728x90, 970x90)
   - "vertical": Skyscraper (160x600, 120x600)
   - "rectangle": Medium rectangle (300x250)

5. RESTART FLASK SERVER:
   After making changes, restart the Flask server for changes to take effect.
"""
