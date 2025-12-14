/**
 * Advanced Browser Fingerprinting Collection
 * Extended fingerprinting with advanced detection techniques
 */

class AdvancedFingerprint {
    constructor(baseFingerprint) {
        this.fingerprint = baseFingerprint || {};
        this.mouseData = {
            movements: [],
            clicks: [],
            startTime: Date.now()
        };
    }

    async collectAdvanced() {
        await Promise.all([
            this.collectEnhancedCanvas(),
            this.collectCSSMediaQueries(),
            this.collectSpeechSynthesis(),
            this.collectGamepads(),
            this.collectSensorAPIs(),
            this.collectPerformanceAPI(),
            this.collectClientHints(),
            this.detectVirtualMachine(),
            this.detectBrowserExtensions(),
            this.collectAdvancedTiming(),
            this.setupAdvancedBehavioral()
        ]);

        return this.fingerprint;
    }

    // ========== ENHANCED CANVAS FINGERPRINTING ==========
    async collectEnhancedCanvas() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 400;
            canvas.height = 200;

            // Test 1: Text rendering with sub-pixel precision
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);

            // Test 2: Gradient rendering
            const gradient = ctx.createLinearGradient(0, 0, 200, 0);
            gradient.addColorStop(0, 'red');
            gradient.addColorStop(0.5, 'green');
            gradient.addColorStop(1, 'blue');
            ctx.fillStyle = gradient;
            ctx.fillRect(0, 30, 200, 30);

            // Test 3: Emoji rendering (OS-specific)
            ctx.font = '48px Arial';
            ctx.fillStyle = '#069';
            ctx.fillText('🎨🔒🌈', 10, 100);

            // Test 4: Complex path rendering
            ctx.beginPath();
            ctx.arc(300, 100, 50, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(255, 0, 0, 0.5)';
            ctx.fill();

            // Test 5: Text with different fonts
            ctx.font = '14px Georgia';
            ctx.fillStyle = '#000';
            ctx.fillText('Canvas Fingerprint Test 123', 10, 150);

            this.fingerprint.canvas_enhanced = canvas.toDataURL();

            // Get canvas pixel data hash
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const pixelHash = this.hashPixelData(imageData.data);
            this.fingerprint.canvas_pixel_hash = pixelHash;

        } catch (e) {
            this.fingerprint.canvas_enhanced_error = e.message;
        }
    }

    hashPixelData(data) {
        let hash = 0;
        for (let i = 0; i < data.length; i += 100) {
            hash = ((hash << 5) - hash) + data[i];
            hash = hash & hash;
        }
        return hash.toString(36);
    }

    // ========== CSS MEDIA QUERIES FINGERPRINTING ==========
    async collectCSSMediaQueries() {
        const mediaQueries = {
            // Pointer capabilities
            'pointer_fine': window.matchMedia('(pointer: fine)').matches,
            'pointer_coarse': window.matchMedia('(pointer: coarse)').matches,
            'pointer_none': window.matchMedia('(pointer: none)').matches,

            // Hover capabilities
            'hover_hover': window.matchMedia('(hover: hover)').matches,
            'hover_none': window.matchMedia('(hover: none)').matches,

            // Any-pointer
            'any_pointer_fine': window.matchMedia('(any-pointer: fine)').matches,
            'any_pointer_coarse': window.matchMedia('(any-pointer: coarse)').matches,
            'any_pointer_none': window.matchMedia('(any-pointer: none)').matches,

            // Any-hover
            'any_hover_hover': window.matchMedia('(any-hover: hover)').matches,
            'any_hover_none': window.matchMedia('(any-hover: none)').matches,

            // Color capabilities
            'color_gamut_srgb': window.matchMedia('(color-gamut: srgb)').matches,
            'color_gamut_p3': window.matchMedia('(color-gamut: p3)').matches,
            'color_gamut_rec2020': window.matchMedia('(color-gamut: rec2020)').matches,

            // Dynamic range
            'dynamic_range_standard': window.matchMedia('(dynamic-range: standard)').matches,
            'dynamic_range_high': window.matchMedia('(dynamic-range: high)').matches,

            // Display mode
            'display_fullscreen': window.matchMedia('(display-mode: fullscreen)').matches,
            'display_standalone': window.matchMedia('(display-mode: standalone)').matches,
            'display_minimal_ui': window.matchMedia('(display-mode: minimal-ui)').matches,
            'display_browser': window.matchMedia('(display-mode: browser)').matches,

            // Orientation
            'orientation_portrait': window.matchMedia('(orientation: portrait)').matches,
            'orientation_landscape': window.matchMedia('(orientation: landscape)').matches,

            // Prefers
            'prefers_reduced_motion': window.matchMedia('(prefers-reduced-motion: reduce)').matches,
            'prefers_color_scheme_dark': window.matchMedia('(prefers-color-scheme: dark)').matches,
            'prefers_color_scheme_light': window.matchMedia('(prefers-color-scheme: light)').matches,
            'prefers_contrast_high': window.matchMedia('(prefers-contrast: high)').matches,
            'prefers_reduced_transparency': window.matchMedia('(prefers-reduced-transparency: reduce)').matches,
        };

        this.fingerprint.css_media_queries = mediaQueries;
        this.fingerprint.css_media_queries_count = Object.values(mediaQueries).filter(v => v).length;
    }

    // ========== SPEECH SYNTHESIS FINGERPRINTING ==========
    async collectSpeechSynthesis() {
        try {
            if ('speechSynthesis' in window) {
                const voices = speechSynthesis.getVoices();

                this.fingerprint.speech_synthesis_support = true;
                this.fingerprint.speech_voices_count = voices.length;
                this.fingerprint.speech_voices = voices.map(v => ({
                    name: v.name,
                    lang: v.lang,
                    default: v.default,
                    localService: v.localService
                }));

                // Create a unique hash from voice names
                const voiceHash = voices.map(v => v.name).join('|');
                this.fingerprint.speech_voice_hash = this.simpleHash(voiceHash);
            } else {
                this.fingerprint.speech_synthesis_support = false;
            }
        } catch (e) {
            this.fingerprint.speech_synthesis_error = e.message;
        }
    }

    // ========== GAMEPAD API DETECTION ==========
    async collectGamepads() {
        try {
            const gamepads = navigator.getGamepads ? navigator.getGamepads() : [];
            const connectedGamepads = Array.from(gamepads).filter(g => g !== null);

            this.fingerprint.gamepad_support = 'getGamepads' in navigator;
            this.fingerprint.gamepads_connected = connectedGamepads.length;

            if (connectedGamepads.length > 0) {
                this.fingerprint.gamepad_ids = connectedGamepads.map(g => ({
                    id: g.id,
                    index: g.index,
                    buttons: g.buttons.length,
                    axes: g.axes.length,
                    mapping: g.mapping
                }));
            }
        } catch (e) {
            this.fingerprint.gamepad_error = e.message;
        }
    }

    // ========== SENSOR APIS DETECTION ==========
    async collectSensorAPIs() {
        const sensors = {
            accelerometer: 'Accelerometer' in window,
            gyroscope: 'Gyroscope' in window,
            magnetometer: 'Magnetometer' in window,
            absolute_orientation: 'AbsoluteOrientationSensor' in window,
            relative_orientation: 'RelativeOrientationSensor' in window,
            ambient_light: 'AmbientLightSensor' in window,
            gravity: 'GravitySensor' in window,
            linear_acceleration: 'LinearAccelerationSensor' in window
        };

        this.fingerprint.sensor_apis = sensors;
        this.fingerprint.sensor_apis_count = Object.values(sensors).filter(v => v).length;

        // Try to detect device orientation support
        if ('DeviceOrientationEvent' in window) {
            this.fingerprint.device_orientation_support = true;
        }

        if ('DeviceMotionEvent' in window) {
            this.fingerprint.device_motion_support = true;
        }
    }

    // ========== PERFORMANCE API FINGERPRINTING ==========
    async collectPerformanceAPI() {
        try {
            if ('performance' in window) {
                const perf = performance;
                const timing = perf.timing;
                const navigation = perf.navigation;

                this.fingerprint.performance_timing = {
                    dom_complete: timing.domComplete - timing.navigationStart,
                    dom_interactive: timing.domInteractive - timing.navigationStart,
                    load_event_end: timing.loadEventEnd - timing.navigationStart,
                    response_end: timing.responseEnd - timing.requestStart,
                    dom_content_loaded: timing.domContentLoadedEventEnd - timing.navigationStart
                };

                this.fingerprint.performance_navigation = {
                    type: navigation.type,
                    redirect_count: navigation.redirectCount
                };

                this.fingerprint.performance_memory = perf.memory ? {
                    js_heap_size_limit: perf.memory.jsHeapSizeLimit,
                    total_js_heap_size: perf.memory.totalJSHeapSize,
                    used_js_heap_size: perf.memory.usedJSHeapSize
                } : null;
            }
        } catch (e) {
            this.fingerprint.performance_error = e.message;
        }
    }

    // ========== CLIENT HINTS DETECTION ==========
    async collectClientHints() {
        try {
            // User-Agent Client Hints (new standard)
            if (navigator.userAgentData) {
                this.fingerprint.client_hints = {
                    brands: navigator.userAgentData.brands,
                    mobile: navigator.userAgentData.mobile,
                    platform: navigator.userAgentData.platform
                };

                // High entropy hints (requires permission)
                try {
                    const highEntropy = await navigator.userAgentData.getHighEntropyValues([
                        'architecture',
                        'model',
                        'platformVersion',
                        'uaFullVersion',
                        'bitness',
                        'fullVersionList'
                    ]);

                    this.fingerprint.client_hints_high_entropy = highEntropy;
                } catch (e) {
                    this.fingerprint.client_hints_high_entropy_error = e.message;
                }
            } else {
                this.fingerprint.client_hints_support = false;
            }
        } catch (e) {
            this.fingerprint.client_hints_error = e.message;
        }
    }

    // ========== VIRTUAL MACHINE DETECTION ==========
    async detectVirtualMachine() {
        const vmIndicators = {
            // Generic hardware
            webgl_vendor_generic: false,
            cpu_cores_low: false,
            memory_low: false,

            // Performance anomalies
            render_performance_low: false,

            // VM-specific strings
            vm_in_user_agent: false,
            vm_in_webgl: false
        };

        // Check WebGL vendor
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const vendor = gl.getParameter(gl.VENDOR).toLowerCase();
            const renderer = gl.getParameter(gl.RENDERER).toLowerCase();

            if (vendor.includes('vmware') || vendor.includes('virtualbox') ||
                renderer.includes('vmware') || renderer.includes('virtualbox') ||
                renderer.includes('llvmpipe') || renderer.includes('software') ||
                renderer.includes('generic')) {
                vmIndicators.webgl_vendor_generic = true;
                vmIndicators.vm_in_webgl = true;
            }
        }

        // Check CPU cores
        if (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2) {
            vmIndicators.cpu_cores_low = true;
        }

        // Check memory
        if (navigator.deviceMemory && navigator.deviceMemory <= 2) {
            vmIndicators.memory_low = true;
        }

        // Check User-Agent
        const ua = navigator.userAgent.toLowerCase();
        if (ua.includes('vm') || ua.includes('virtual')) {
            vmIndicators.vm_in_user_agent = true;
        }

        // Performance test
        const start = performance.now();
        for (let i = 0; i < 1000000; i++) {
            Math.sqrt(i);
        }
        const elapsed = performance.now() - start;

        if (elapsed > 50) {
            vmIndicators.render_performance_low = true;
        }

        this.fingerprint.vm_detection = vmIndicators;
        this.fingerprint.vm_likelihood = Object.values(vmIndicators).filter(v => v).length > 2 ? 'high' :
                                        Object.values(vmIndicators).filter(v => v).length > 0 ? 'medium' : 'low';
    }

    // ========== BROWSER EXTENSION DETECTION ==========
    async detectBrowserExtensions() {
        const extensions = {
            // Common ad blockers
            adblock_detected: false,
            ublock_detected: false,

            // Privacy extensions
            privacy_badger: false,
            ghostery: false,

            // Developer extensions
            react_devtools: false,
            vue_devtools: false,

            // Total detected
            total_detected: 0
        };

        // Check for resource blocking (ad blocker indicator)
        const testAd = document.createElement('div');
        testAd.className = 'adBanner ad-banner ads advertisement';
        testAd.style.cssText = 'position:absolute;top:-999px;left:-999px;width:1px;height:1px;';
        document.body.appendChild(testAd);

        setTimeout(() => {
            if (testAd.offsetHeight === 0 || window.getComputedStyle(testAd).display === 'none') {
                extensions.adblock_detected = true;
                extensions.total_detected++;
            }
            document.body.removeChild(testAd);
        }, 100);

        // Check for React DevTools
        if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
            extensions.react_devtools = true;
            extensions.total_detected++;
        }

        // Check for Vue DevTools
        if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__) {
            extensions.vue_devtools = true;
            extensions.total_detected++;
        }

        this.fingerprint.browser_extensions = extensions;
    }

    // ========== ADVANCED TIMING ANALYSIS ==========
    async collectAdvancedTiming() {
        const timing = {
            page_load_time: Date.now() - this.mouseData.startTime,
            time_to_first_interaction: null,
            time_to_first_click: null,
            time_to_first_scroll: null,
            form_interaction_time: 0
        };

        this.fingerprint.advanced_timing = timing;

        // These will be updated by behavioral tracking
        window.advancedTiming = timing;
    }

    // ========== ADVANCED BEHAVIORAL TRACKING ==========
    setupAdvancedBehavioral() {
        // Advanced mouse tracking
        let mouseMoveCount = 0;
        const mouseMovements = [];
        const mouseVelocities = [];
        const mouseAccelerations = [];
        let lastMousePos = null;
        let lastMouseTime = null;
        let lastVelocity = null;

        document.addEventListener('mousemove', (e) => {
            const currentTime = Date.now();
            const currentPos = { x: e.clientX, y: e.clientY };

            if (lastMousePos && lastMouseTime) {
                const deltaTime = (currentTime - lastMouseTime) / 1000; // seconds
                const deltaX = currentPos.x - lastMousePos.x;
                const deltaY = currentPos.y - lastMousePos.y;
                const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
                const velocity = distance / deltaTime;

                mouseVelocities.push(velocity);

                if (lastVelocity !== null) {
                    const acceleration = (velocity - lastVelocity) / deltaTime;
                    mouseAccelerations.push(acceleration);
                }

                lastVelocity = velocity;

                // Store movement pattern (sample every 10th movement)
                if (mouseMoveCount % 10 === 0) {
                    mouseMovements.push({
                        x: currentPos.x,
                        y: currentPos.y,
                        time: currentTime,
                        velocity: velocity.toFixed(2)
                    });
                }
            }

            lastMousePos = currentPos;
            lastMouseTime = currentTime;
            mouseMoveCount++;

            // Update timing
            if (window.advancedTiming && !window.advancedTiming.time_to_first_interaction) {
                window.advancedTiming.time_to_first_interaction = currentTime - this.mouseData.startTime;
            }
        });

        // Click timing and patterns
        const clickTimings = [];
        let lastClickTime = null;

        document.addEventListener('click', (e) => {
            const currentTime = Date.now();

            if (lastClickTime) {
                clickTimings.push(currentTime - lastClickTime);
            }

            lastClickTime = currentTime;

            // Update timing
            if (window.advancedTiming && !window.advancedTiming.time_to_first_click) {
                window.advancedTiming.time_to_first_click = currentTime - this.mouseData.startTime;
            }
        });

        // Scroll tracking
        let scrollCount = 0;
        const scrollVelocities = [];
        let lastScrollPos = 0;
        let lastScrollTime = null;

        document.addEventListener('scroll', (e) => {
            const currentTime = Date.now();
            const currentScrollPos = window.scrollY;

            if (lastScrollTime) {
                const deltaTime = (currentTime - lastScrollTime) / 1000;
                const deltaScroll = Math.abs(currentScrollPos - lastScrollPos);
                const scrollVelocity = deltaScroll / deltaTime;
                scrollVelocities.push(scrollVelocity);
            }

            lastScrollPos = currentScrollPos;
            lastScrollTime = currentTime;
            scrollCount++;

            // Update timing
            if (window.advancedTiming && !window.advancedTiming.time_to_first_scroll) {
                window.advancedTiming.time_to_first_scroll = currentTime - this.mouseData.startTime;
            }
        });

        // Keyboard timing (dwell time and flight time)
        const keyDownTimes = {};
        const dwellTimes = [];
        const flightTimes = [];
        let lastKeyUpTime = null;

        document.addEventListener('keydown', (e) => {
            const currentTime = Date.now();
            keyDownTimes[e.key] = currentTime;
        });

        document.addEventListener('keyup', (e) => {
            const currentTime = Date.now();

            // Dwell time (how long key was pressed)
            if (keyDownTimes[e.key]) {
                const dwellTime = currentTime - keyDownTimes[e.key];
                dwellTimes.push(dwellTime);
                delete keyDownTimes[e.key];
            }

            // Flight time (time between key releases)
            if (lastKeyUpTime) {
                const flightTime = currentTime - lastKeyUpTime;
                flightTimes.push(flightTime);
            }

            lastKeyUpTime = currentTime;
        });

        // Store behavioral data after 5 seconds
        setTimeout(() => {
            this.fingerprint.mouse_behavior = {
                total_movements: mouseMoveCount,
                average_velocity: mouseVelocities.length > 0 ?
                    (mouseVelocities.reduce((a, b) => a + b, 0) / mouseVelocities.length).toFixed(2) : 0,
                max_velocity: mouseVelocities.length > 0 ? Math.max(...mouseVelocities).toFixed(2) : 0,
                average_acceleration: mouseAccelerations.length > 0 ?
                    (mouseAccelerations.reduce((a, b) => a + b, 0) / mouseAccelerations.length).toFixed(2) : 0,
                movement_pattern_samples: mouseMovements.slice(0, 20),
                has_human_curves: this.detectHumanCurves(mouseMovements)
            };

            this.fingerprint.click_behavior = {
                total_clicks: clickTimings.length + 1,
                average_click_interval: clickTimings.length > 0 ?
                    (clickTimings.reduce((a, b) => a + b, 0) / clickTimings.length).toFixed(2) : 0,
                click_rhythm_variance: this.calculateVariance(clickTimings)
            };

            this.fingerprint.scroll_behavior = {
                total_scrolls: scrollCount,
                average_scroll_velocity: scrollVelocities.length > 0 ?
                    (scrollVelocities.reduce((a, b) => a + b, 0) / scrollVelocities.length).toFixed(2) : 0,
                has_scrolled: scrollCount > 0
            };

            this.fingerprint.keyboard_behavior = {
                average_dwell_time: dwellTimes.length > 0 ?
                    (dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length).toFixed(2) : 0,
                average_flight_time: flightTimes.length > 0 ?
                    (flightTimes.reduce((a, b) => a + b, 0) / flightTimes.length).toFixed(2) : 0,
                typing_rhythm: this.calculateVariance(flightTimes)
            };
        }, 5000);
    }

    detectHumanCurves(movements) {
        if (movements.length < 5) return false;

        // Check if movement follows curved path (not straight lines)
        let curveDetected = false;
        for (let i = 2; i < movements.length; i++) {
            const p1 = movements[i - 2];
            const p2 = movements[i - 1];
            const p3 = movements[i];

            // Calculate angle change
            const angle1 = Math.atan2(p2.y - p1.y, p2.x - p1.x);
            const angle2 = Math.atan2(p3.y - p2.y, p3.x - p2.x);
            const angleChange = Math.abs(angle2 - angle1);

            // Humans create curves with gradual angle changes
            if (angleChange > 0.1 && angleChange < Math.PI / 2) {
                curveDetected = true;
                break;
            }
        }

        return curveDetected;
    }

    calculateVariance(arr) {
        if (arr.length === 0) return 0;
        const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
        const variance = arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
        return variance.toFixed(2);
    }

    simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(36);
    }
}

// Export for use in analysis.js
window.AdvancedFingerprint = AdvancedFingerprint;
