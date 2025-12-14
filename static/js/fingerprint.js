/**
 * Comprehensive Browser Fingerprinting Collection
 * Collects extensive browser and device information for analysis
 */

class BrowserFingerprint {
    constructor() {
        this.fingerprint = {};
        this.startTime = Date.now();
    }

    async collect() {
        // Collect all fingerprint data
        await Promise.all([
            this.collectBasicInfo(),
            this.collectNavigatorInfo(),
            this.collectScreenInfo(),
            this.collectCanvasFingerprint(),
            this.collectWebGLFingerprint(),
            this.collectAudioFingerprint(),
            this.collectPlugins(),
            this.collectFonts(),
            this.collectTimezone(),
            this.collectBatteryInfo(),
            this.collectConnectionInfo(),
            this.collectMediaDevices(),
            this.detectAutomation(),
            this.detectHeadless(),
            this.collectWebRTC(),
            this.collectBehavioralData()
        ]);

        // Collect advanced fingerprints
        if (window.AdvancedFingerprint) {
            const advanced = new AdvancedFingerprint(this.fingerprint);
            this.fingerprint = await advanced.collectAdvanced();
        }

        return this.fingerprint;
    }

    collectBasicInfo() {
        this.fingerprint.user_agent = navigator.userAgent;
        this.fingerprint.platform = navigator.platform;
        this.fingerprint.language = navigator.language;
        this.fingerprint.languages = navigator.languages || [];
        this.fingerprint.cookie_enabled = navigator.cookieEnabled;
        this.fingerprint.do_not_track = navigator.doNotTrack;
        this.fingerprint.online = navigator.onLine;
    }

    collectNavigatorInfo() {
        this.fingerprint.app_name = navigator.appName;
        this.fingerprint.app_version = navigator.appVersion;
        this.fingerprint.product = navigator.product;
        this.fingerprint.product_sub = navigator.productSub;
        this.fingerprint.vendor = navigator.vendor;
        this.fingerprint.vendor_sub = navigator.vendorSub;
        this.fingerprint.hardware_concurrency = navigator.hardwareConcurrency || 0;
        this.fingerprint.device_memory = navigator.deviceMemory || 0;
        this.fingerprint.max_touch_points = navigator.maxTouchPoints || 0;
    }

    collectScreenInfo() {
        this.fingerprint.screen_width = screen.width;
        this.fingerprint.screen_height = screen.height;
        this.fingerprint.screen_avail_width = screen.availWidth;
        this.fingerprint.screen_avail_height = screen.availHeight;
        this.fingerprint.screen_color_depth = screen.colorDepth;
        this.fingerprint.screen_pixel_depth = screen.pixelDepth;
        this.fingerprint.window_inner_width = window.innerWidth;
        this.fingerprint.window_inner_height = window.innerHeight;
        this.fingerprint.window_outer_width = window.outerWidth;
        this.fingerprint.window_outer_height = window.outerHeight;
        this.fingerprint.device_pixel_ratio = window.devicePixelRatio || 1;
    }

    async collectCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');

            canvas.width = 200;
            canvas.height = 50;

            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('Canvas Fingerprint 🔒', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Canvas Fingerprint 🔒', 4, 17);

            this.fingerprint.canvas = canvas.toDataURL();
        } catch (e) {
            this.fingerprint.canvas = 'blocked';
        }
    }

    async collectWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

            if (gl) {
                this.fingerprint.webgl_vendor = gl.getParameter(gl.VENDOR);
                this.fingerprint.webgl_renderer = gl.getParameter(gl.RENDERER);
                this.fingerprint.webgl_version = gl.getParameter(gl.VERSION);
                this.fingerprint.webgl_shading_language_version = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);

                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    this.fingerprint.webgl_unmasked_vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                    this.fingerprint.webgl_unmasked_renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                }
            } else {
                this.fingerprint.webgl_support = false;
            }
        } catch (e) {
            this.fingerprint.webgl_error = e.message;
        }
    }

    async collectAudioFingerprint() {
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) {
                this.fingerprint.audio_support = false;
                return;
            }

            const context = new AudioContext();
            const oscillator = context.createOscillator();
            const analyser = context.createAnalyser();
            const gainNode = context.createGain();
            const scriptProcessor = context.createScriptProcessor(4096, 1, 1);

            gainNode.gain.value = 0;
            oscillator.type = 'triangle';
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(context.destination);
            oscillator.start(0);

            scriptProcessor.onaudioprocess = (event) => {
                const output = event.outputBuffer.getChannelData(0);
                let sum = 0;
                for (let i = 0; i < output.length; i++) {
                    sum += Math.abs(output[i]);
                }
                this.fingerprint.audio_fingerprint = sum.toString();
                oscillator.stop();
                scriptProcessor.disconnect();
            };

            this.fingerprint.audio_context_state = context.state;
            this.fingerprint.audio_sample_rate = context.sampleRate;
        } catch (e) {
            this.fingerprint.audio_error = e.message;
        }
    }

    collectPlugins() {
        const plugins = [];
        for (let i = 0; i < navigator.plugins.length; i++) {
            const plugin = navigator.plugins[i];
            plugins.push({
                name: plugin.name,
                description: plugin.description,
                filename: plugin.filename
            });
        }
        this.fingerprint.plugins = plugins.length;
        this.fingerprint.plugins_list = plugins;
    }

    async collectFonts() {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
            'Arial', 'Verdana', 'Times New Roman', 'Courier New',
            'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
            'Trebuchet MS', 'Arial Black', 'Impact', 'Calibri', 'Cambria'
        ];

        const detectedFonts = [];
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');

        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';

        for (const testFont of testFonts) {
            let detected = false;
            for (const baseFont of baseFonts) {
                ctx.font = `${testSize} ${baseFont}`;
                const baseWidth = ctx.measureText(testString).width;

                ctx.font = `${testSize} ${testFont}, ${baseFont}`;
                const testWidth = ctx.measureText(testString).width;

                if (baseWidth !== testWidth) {
                    detected = true;
                    break;
                }
            }
            if (detected) {
                detectedFonts.push(testFont);
            }
        }

        this.fingerprint.fonts = detectedFonts;
        this.fingerprint.fonts_count = detectedFonts.length;
    }

    collectTimezone() {
        this.fingerprint.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        this.fingerprint.timezone_offset = new Date().getTimezoneOffset();
    }

    async collectBatteryInfo() {
        try {
            if ('getBattery' in navigator) {
                const battery = await navigator.getBattery();
                this.fingerprint.battery_charging = battery.charging;
                this.fingerprint.battery_level = battery.level;
                this.fingerprint.battery_charging_time = battery.chargingTime;
                this.fingerprint.battery_discharging_time = battery.dischargingTime;
            } else {
                this.fingerprint.battery_support = false;
            }
        } catch (e) {
            this.fingerprint.battery_error = e.message;
        }
    }

    async collectConnectionInfo() {
        try {
            const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            if (connection) {
                this.fingerprint.connection_type = connection.effectiveType;
                this.fingerprint.connection_downlink = connection.downlink;
                this.fingerprint.connection_rtt = connection.rtt;
                this.fingerprint.connection_save_data = connection.saveData;
            }
        } catch (e) {
            this.fingerprint.connection_error = e.message;
        }
    }

    async collectMediaDevices() {
        try {
            if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
                const devices = await navigator.mediaDevices.enumerateDevices();
                this.fingerprint.media_devices_count = devices.length;
                this.fingerprint.audio_input_count = devices.filter(d => d.kind === 'audioinput').length;
                this.fingerprint.video_input_count = devices.filter(d => d.kind === 'videoinput').length;
                this.fingerprint.audio_output_count = devices.filter(d => d.kind === 'audiooutput').length;
            }
        } catch (e) {
            this.fingerprint.media_devices_error = e.message;
        }
    }

    detectAutomation() {
        // Check for WebDriver
        this.fingerprint.webdriver = navigator.webdriver || false;

        // Check for automation properties
        this.fingerprint.__nightmare = !!window.__nightmare;
        this.fingerprint.__phantomas = !!window.__phantomas;
        this.fingerprint.callPhantom = !!window.callPhantom;
        this.fingerprint._phantom = !!window._phantom;
        this.fingerprint.__selenium = !!window.__selenium;
        this.fingerprint.__webdriver = !!window.__webdriver;
        this.fingerprint.__driver = !!window.__driver;

        // Check for Selenium IDE
        this.fingerprint.selenium_ide = !!document.documentElement.getAttribute('selenium');
        this.fingerprint.selenium_webdriver = !!document.documentElement.getAttribute('webdriver');

        // Check for Chrome automation
        this.fingerprint.chrome = !!window.chrome;
        this.fingerprint.chrome_runtime = !!(window.chrome && window.chrome.runtime);

        // Check permissions
        try {
            this.fingerprint.notification_permission = Notification.permission;
        } catch (e) {
            this.fingerprint.notification_permission = 'unavailable';
        }
    }

    detectHeadless() {
        // Headless detection
        this.fingerprint.headless = false;

        // Check for missing features
        if (!navigator.plugins || navigator.plugins.length === 0) {
            this.fingerprint.headless_indicator_no_plugins = true;
        }

        // Check for webdriver
        if (navigator.webdriver) {
            this.fingerprint.headless_indicator_webdriver = true;
            this.fingerprint.headless = true;
        }

        // Check user agent
        if (/HeadlessChrome|PhantomJS/i.test(navigator.userAgent)) {
            this.fingerprint.headless_indicator_ua = true;
            this.fingerprint.headless = true;
        }

        // Check for missing window properties
        if (!window.outerWidth || !window.outerHeight) {
            this.fingerprint.headless_indicator_window_size = true;
        }
    }

    async collectWebRTC() {
        try {
            const RTCPeerConnection = window.RTCPeerConnection ||
                                     window.mozRTCPeerConnection ||
                                     window.webkitRTCPeerConnection;

            if (!RTCPeerConnection) {
                this.fingerprint.webrtc_support = false;
                return;
            }

            const pc = new RTCPeerConnection({
                iceServers: [{urls: 'stun:stun.l.google.com:19302'}]
            });

            const ips = [];

            pc.onicecandidate = (ice) => {
                if (!ice || !ice.candidate || !ice.candidate.candidate) return;

                const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/;
                const match = ipRegex.exec(ice.candidate.candidate);

                if (match) {
                    ips.push(match[1]);
                }
            };

            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));

            setTimeout(() => {
                this.fingerprint.webrtc_ips = [...new Set(ips)];
                pc.close();
            }, 2000);

        } catch (e) {
            this.fingerprint.webrtc_error = e.message;
        }
    }

    collectBehavioralData() {
        // Track behavioral signals
        this.fingerprint.has_mouse_movement = false;
        this.fingerprint.has_keyboard_input = false;
        this.fingerprint.has_scroll = false;
        this.fingerprint.has_page_focus = document.hasFocus();
        this.fingerprint.touch_support = 'ontouchstart' in window;

        // Mouse movement
        document.addEventListener('mousemove', () => {
            this.fingerprint.has_mouse_movement = true;
        }, { once: true });

        // Keyboard input
        document.addEventListener('keydown', () => {
            this.fingerprint.has_keyboard_input = true;
        }, { once: true });

        // Scroll
        window.addEventListener('scroll', () => {
            this.fingerprint.has_scroll = true;
        }, { once: true });
    }
}

// Export for use in analysis.js
window.BrowserFingerprint = BrowserFingerprint;
