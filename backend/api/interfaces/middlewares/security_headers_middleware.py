# Security headers for every HTTP response (API, SPA shell, static assets).
#
# Until now no response carried clickjacking / MIME-sniffing / referrer
# headers, so a browser embedding the app in an iframe (clickjacking) or
# sniffing a JSON error body as executable content was left to browser
# defaults, and full referrer URLs leaked to cross-origin links. There was
# also no Strict-Transport-Security, so a first visit over plain HTTP in
# production could be downgraded (SSL stripping) before any server-side
# HTTPS redirect was ever seen. HSTS is sent unconditionally here:
# browsers ignore it when received over plain HTTP, so development over
# http://localhost is unaffected, and in production every response is
# already HTTPS.
#
# This is a pure ASGI middleware, not a BaseHTTPMiddleware subclass, so
# it only rewrites the response-start headers and never buffers the
# body: the ai-chat SSE stream passes through untouched. It sets a
# header only when the downstream response does not already carry one,
# so the SPA shell's explicit Cache-Control and any future per-route
# header are never overwritten. No Content-Security-Policy is set here:
# the Vite SPA relies on inline styles/scripts, so a CSP would need a
# per-build nonce design of its own.
_SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"strict-origin-when-cross-origin",
    # Isolate the app's top-level window from a cross-origin opener, so
    # a page that links to the app cannot retain a handle to it (and
    # vice versa) for cross-window attacks. same-origin-allow-popups
    # rather than plain same-origin: the app currently opens no popups
    # (SSO is full-page navigation), but allow-popups keeps any future
    # popup flow working instead of breaking it. Deliberately no
    # Cross-Origin-Resource-Policy here: the frontend may be hosted
    # separately from the backend and fetch it cross-origin under CORS,
    # which a same-origin CORP would block.
    b"cross-origin-opener-policy": b"same-origin-allow-popups",
    b"strict-transport-security": b"max-age=31536000; includeSubDomains",
    # The SPA uses no camera, microphone, or geolocation (verified by
    # grep over frontend/app/src), so disable those powerful features
    # outright: a compromised third-party script embedded in the page
    # cannot then prompt for them on the app's origin. Likewise it
    # uses no Payment Request API / Stripe Elements (Stripe is only
    # configured via dashboard links) and never reads the clipboard
    # (it only writes: writeText in ai-chat plus an execCommand copy
    # fallback), so payment and clipboard-read are disabled too:
    # clipboard-read in particular could otherwise let such a script
    # prompt to read a just-copied password or token. Display capture
    # is disabled for the same reason (verified by grep: the SPA never
    # calls getDisplayMedia, so no screen-sharing flow exists to break).
    # Fullscreen is disabled for the same reason (verified by grep: the
    # SPA never calls requestFullscreen and has no video/audio element,
    # so no fullscreen flow exists to break; a compromised script could
    # otherwise fullscreen-spoof the app UI). The motion/environmental
    # sensors are disabled for the same reason (verified by grep: the
    # SPA never uses DeviceMotion/DeviceOrientation or the
    # Accelerometer/Gyroscope/Magnetometer sensor APIs, so no
    # sensor-driven flow exists to break; a compromised script could
    # otherwise read device motion for fingerprinting). XR spatial
    # tracking is disabled for the same reason (verified by grep: the
    # SPA has no WebXR use and no XR dependency, so no immersive
    # flow exists to break; a compromised script could otherwise
    # start an immersive session for spoofing or fingerprinting).
    # Idle detection is disabled for the same reason (verified by
    # grep: the SPA never uses IdleDetector, so no idle-presence
    # flow exists to break; a compromised script could otherwise
    # learn when the user is away from the keyboard).
    # Picture-in-picture is disabled for the same reason (verified
    # by grep: the SPA has no video/audio element and never calls
    # requestPictureInPicture, so no PiP flow exists to break; a
    # compromised script could otherwise pop app content out into
    # a floating window for UI spoofing).
    # Browsing topics and attribution reporting are disabled for the
    # same reason (verified by grep: the SPA never calls
    # navigator.browsingTopics and uses no attributionsrc /
    # registerSource / registerTrigger, so no ad-tracking flow exists
    # to break; a compromised script could otherwise use them to
    # fingerprint the user or attribute conversions on the app's
    # origin).
    # Window management is disabled for the same reason (verified by
    # grep: the SPA never calls getScreenDetails and has no multi-screen
    # flow, so no window-placement flow exists to break; a compromised
    # script could otherwise enumerate the user's screens and place
    # windows on them for UI spoofing).
    # Keyboard map is disabled for the same reason (verified by grep:
    # the SPA never calls getLayoutMap and has no keyboard-layout
    # flow, so no layout-dependent feature exists to break; a
    # compromised script could otherwise read the user's keyboard
    # layout for fingerprinting).
    # Ambient light sensor is disabled for the same reason (verified
    # by grep: the SPA never uses AmbientLightSensor and has no
    # brightness-adaptive flow, so no sensor-driven feature exists
    # to break; a compromised script could otherwise read ambient
    # light levels for fingerprinting).
    # Screen wake lock is disabled for the same reason (verified by
    # grep: the SPA never calls navigator.wakeLock and has no
    # keep-awake flow, so no wake-lock feature exists to break; a
    # compromised script could otherwise keep the screen awake to
    # aid fingerprinting or annoy the user).
    # The device-transport APIs are disabled for the same reason
    # (verified by grep: the SPA never calls navigator.usb /
    # navigator.bluetooth / navigator.hid / navigator.nfc and has no
    # such dependency, so no WebUSB/WebBluetooth/WebHID/WebNFC flow
    # exists to break; a compromised script could otherwise talk to
    # plugged-in devices on the app's origin). This does NOT break
    # passkey login/registration: that goes through WebAuthn
    # (navigator.credentials via @simplewebauthn/browser), which is
    # gated by the publickey-credentials-get/create directives, not
    # by these transport directives — the browser talks CTAP to USB /
    # BLE / NFC authenticators internally, so those authenticators
    # keep working with the transport APIs disabled. Serial is
    # disabled for the same reason (verified by grep: the SPA never
    # calls navigator.serial and has no Web Serial flow, so no
    # serial-device feature exists to break; a compromised script
    # could otherwise talk to a plugged-in serial device). Gamepad
    # is disabled for the same reason (verified by grep: the SPA
    # never calls navigator.getGamepads and has no gamepad flow, so
    # no controller feature exists to break; a compromised script
    # could otherwise enumerate connected gamepads for
    # fingerprinting). Web share is disabled for the same reason
    # (verified by grep: the SPA never calls navigator.share and
    # has no share-sheet flow — sharing is via copy buttons using
    # clipboard-write, a separate directive left alone — so no
    # share flow exists to break; a compromised script could
    # otherwise open the OS share sheet on the app's origin).
    # Clipboard-write is a separate directive and is deliberately left
    # alone, as are the WebAuthn directives: passkey login/registration
    # must keep working, including USB/BLE/NFC authenticators.
    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=(), clipboard-read=(), display-capture=(), fullscreen=(), accelerometer=(), gyroscope=(), magnetometer=(), xr-spatial-tracking=(), idle-detection=(), picture-in-picture=(), browsing-topics=(), attribution-reporting=(), window-management=(), keyboard-map=(), ambient-light-sensor=(), wake-lock=(), usb=(), bluetooth=(), hid=(), nfc=(), serial=(), gamepad=(), web-share=()",
}


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in _SECURITY_HEADERS.items():
                    if name not in present:
                        headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
