"""
Dynamic Instrumentation Engine

Provides Frida-like capabilities for runtime process instrumentation,
hooking, and manipulation. This is the core engine for dynamic analysis
and security control bypass.

Based on "The Modern Hacker's Playbook" - Part 2.1: Dynamic Instrumentation
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logging.warning("Frida not available. Install with: pip install frida frida-tools")


class InstrumentationMode(Enum):
    """Instrumentation attachment modes"""

    ATTACH = "attach"  # Attach to running process
    SPAWN = "spawn"  # Spawn process with instrumentation
    REMOTE = "remote"  # Remote device instrumentation


class TargetPlatform(Enum):
    """Supported target platforms"""

    WINDOWS = "windows"
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    MACOS = "macos"


@dataclass
class InstrumentationTarget:
    """Target process information"""

    pid: Optional[int] = None
    process_name: Optional[str] = None
    package_name: Optional[str] = None  # For mobile apps
    spawn_args: Optional[List[str]] = None
    platform: TargetPlatform = TargetPlatform.LINUX
    device_id: Optional[str] = None  # For remote devices


@dataclass
class HookResult:
    """Result from a hook execution"""

    function_name: str
    args: List[Any]
    return_value: Any
    modified: bool = False
    backtrace: Optional[List[str]] = None
    timestamp: float = 0.0
    thread_id: int = 0


@dataclass
class InstrumentationSession:
    """Active instrumentation session"""

    target: InstrumentationTarget
    session: Any  # Frida session object
    script: Any  # Frida script object
    hooks: Dict[str, Callable] = field(default_factory=dict)
    intercepted_data: List[HookResult] = field(default_factory=list)


class DynamicInstrumentationEngine:
    """
    Advanced dynamic instrumentation engine for runtime code manipulation.

    Capabilities:
    - Function hooking and interception
    - Runtime security bypass (root detection, SSL pinning, anti-debug)
    - Memory manipulation and dumping
    - API call tracing
    - Cryptographic data extraction
    - Code injection and patching

    Example:
        >>> engine = DynamicInstrumentationEngine()
        >>> target = InstrumentationTarget(process_name="target_app")
        >>> session = engine.attach(target)
        >>> engine.bypass_root_detection(session)
        >>> engine.dump_decrypted_data(session, "AES")
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sessions: Dict[str, InstrumentationSession] = {}
        self.script_cache: Dict[str, str] = {}

        if not FRIDA_AVAILABLE:
            self.logger.error("Frida is not available. Install with: pip install frida frida-tools")

    def attach(self, target: InstrumentationTarget) -> Optional[InstrumentationSession]:
        """
        Attach to a target process or spawn with instrumentation.

        Args:
            target: Target process information

        Returns:
            InstrumentationSession if successful, None otherwise
        """
        if not FRIDA_AVAILABLE:
            self.logger.error("Frida not available")
            return None

        try:
            # Select device
            device = self._get_device(target)

            # Attach or spawn
            if target.pid:
                self.logger.info(f"Attaching to PID {target.pid}")
                session = device.attach(target.pid)
            elif target.process_name:
                # Try to find running process
                processes = device.enumerate_processes()
                matched = [p for p in processes if target.process_name.lower() in p.name.lower()]

                if matched:
                    self.logger.info(
                        f"Attaching to existing process: {matched[0].name} (PID {matched[0].pid})"
                    )
                    session = device.attach(matched[0].pid)
                else:
                    # Spawn new process
                    self.logger.info(f"Spawning new process: {target.process_name}")
                    pid = device.spawn([target.process_name] + (target.spawn_args or []))
                    session = device.attach(pid)
                    device.resume(pid)
            elif target.package_name:
                # Mobile app package
                self.logger.info(f"Spawning mobile app: {target.package_name}")
                pid = device.spawn([target.package_name])
                session = device.attach(pid)
                device.resume(pid)
            else:
                self.logger.error("No valid target specified")
                return None

            # Create session
            instrumentation_session = InstrumentationSession(
                target=target, session=session, script=None
            )

            session_id = f"session_{id(session)}"
            self.sessions[session_id] = instrumentation_session

            self.logger.info(f"Instrumentation session created: {session_id}")
            return instrumentation_session

        except Exception as e:
            self.logger.error(f"Failed to attach/spawn: {e}")
            return None

    def _get_device(self, target: InstrumentationTarget):
        """Get appropriate Frida device based on target platform"""
        if target.platform == TargetPlatform.ANDROID:
            devices = frida.enumerate_devices()
            android_devices = [d for d in devices if "usb" in d.id or "emulator" in d.id]
            if android_devices:
                return android_devices[0]
            return frida.get_usb_device()
        elif target.platform == TargetPlatform.IOS:
            return frida.get_usb_device()
        elif target.device_id:
            return frida.get_device(target.device_id)
        else:
            return frida.get_local_device()

    def execute_script(
        self,
        session: InstrumentationSession,
        script_code: str,
        message_handler: Optional[Callable] = None,
    ) -> bool:
        """
        Execute a Frida JavaScript script in the target process.

        Args:
            session: Active instrumentation session
            script_code: JavaScript code to execute
            message_handler: Optional callback for script messages

        Returns:
            True if successful
        """
        try:
            script = session.session.create_script(script_code)

            if message_handler:
                script.on("message", message_handler)
            else:
                script.on("message", self._default_message_handler)

            script.load()
            session.script = script

            self.logger.info("Script loaded successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to execute script: {e}")
            return False

    def _default_message_handler(self, message: Dict, data: Optional[bytes]):
        """Default handler for script messages"""
        if message["type"] == "send":
            self.logger.info(f"[Script] {message['payload']}")
        elif message["type"] == "error":
            self.logger.error(f"[Script Error] {message['stack']}")

    # ========== OFFENSIVE BYPASS TECHNIQUES ==========

    def bypass_root_detection(self, session: InstrumentationSession) -> bool:
        """
        Bypass root/jailbreak detection mechanisms.

        Hooks common root detection functions and forces them to return false.
        Based on Modern Hacker's Playbook: Offensive Use Case 1

        Args:
            session: Active instrumentation session

        Returns:
            True if bypass applied successfully
        """
        script = """
        // Android Root Detection Bypass
        if (Java.available) {
            Java.perform(function() {
                console.log("[*] Bypassing Android root detection...");

                // Common root detection class hooks
                var rootDetectionClasses = [
                    "com.scottyab.rootbeer.RootBeer",
                    "com.jrummy.root.utils.RootUtils",
                    "com.topjohnwu.superuser.Shell"
                ];

                rootDetectionClasses.forEach(function(className) {
                    try {
                        var RootClass = Java.use(className);

                        // Hook all methods that contain "root" or "su"
                        var methods = RootClass.class.getDeclaredMethods();
                        methods.forEach(function(method) {
                            var methodName = method.getName();
                            if (methodName.toLowerCase().includes("root") ||
                                methodName.toLowerCase().includes("su")) {
                                try {
                                    RootClass[methodName].implementation = function() {
                                        console.log("[*] Bypassed: " + className + "." + methodName);
                                        return false;
                                    };
                                } catch(e) {}
                            }
                        });
                    } catch(e) {
                        // Class not found, skip
                    }
                });

                // Generic isRooted bypass
                try {
                    var Build = Java.use("android.os.Build");
                    var tags = Build.TAGS.value;
                    if (tags.includes("test-keys")) {
                        Build.TAGS.value = tags.replace("test-keys", "release-keys");
                        console.log("[*] Patched Build.TAGS");
                    }
                } catch(e) {}

                console.log("[+] Root detection bypass complete");
            });
        }

        // iOS Jailbreak Detection Bypass
        if (ObjC.available) {
            console.log("[*] Bypassing iOS jailbreak detection...");

            // Hook file existence checks for jailbreak indicators
            var NSFileManager = ObjC.classes.NSFileManager;
            var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];

            Interceptor.attach(fileExistsAtPath.implementation, {
                onEnter: function(args) {
                    this.path = ObjC.Object(args[2]).toString();
                },
                onLeave: function(retval) {
                    // Block detection of jailbreak files
                    var jailbreakPaths = [
                        "/Applications/Cydia.app",
                        "/bin/bash",
                        "/usr/sbin/sshd",
                        "/etc/apt",
                        "/private/var/lib/apt/"
                    ];

                    if (jailbreakPaths.some(path => this.path.includes(path))) {
                        console.log("[*] Blocked jailbreak path check: " + this.path);
                        retval.replace(0);
                    }
                }
            });

            console.log("[+] Jailbreak detection bypass complete");
        }
        """

        return self.execute_script(session, script)

    def bypass_ssl_pinning(self, session: InstrumentationSession) -> bool:
        """
        Bypass SSL certificate pinning.

        Disables certificate validation to allow MITM interception.

        Args:
            session: Active instrumentation session

        Returns:
            True if bypass applied successfully
        """
        script = """
        // Android SSL Pinning Bypass
        if (Java.available) {
            Java.perform(function() {
                console.log("[*] Bypassing Android SSL pinning...");

                // TrustManager bypass
                try {
                    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                    var SSLContext = Java.use('javax.net.ssl.SSLContext');

                    var TrustManager = Java.registerClass({
                        name: 'com.reveng.TrustManager',
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function(chain, authType) {},
                            checkServerTrusted: function(chain, authType) {},
                            getAcceptedIssuers: function() { return []; }
                        }
                    });

                    var TrustManagers = [TrustManager.$new()];
                    var SSLContext_init = SSLContext.init.overload(
                        '[Ljavax.net.ssl.KeyManager;',
                        '[Ljavax.net.ssl.TrustManager;',
                        'java.security.SecureRandom'
                    );

                    Interceptor.attach(SSLContext_init.implementation, {
                        onEnter: function(args) {
                            args[1] = TrustManagers;
                            console.log("[*] SSL Pinning bypassed");
                        }
                    });
                } catch(e) {
                    console.log("[-] TrustManager bypass failed: " + e);
                }

                // OkHttp Certificate Pinner bypass
                try {
                    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                        console.log("[*] OkHttp pinning bypassed");
                    };
                } catch(e) {}

                console.log("[+] SSL pinning bypass complete");
            });
        }

        // iOS SSL Pinning Bypass
        if (ObjC.available) {
            console.log("[*] Bypassing iOS SSL pinning...");

            // NSURLSession bypass
            var NSURLSession = ObjC.classes.NSURLSession;
            var invalidate = NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'];

            if (invalidate) {
                Interceptor.attach(invalidate.implementation, {
                    onEnter: function(args) {
                        console.log("[*] SSL challenge intercepted");
                        // Force accept all certificates
                        var credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
                        var completionHandler = new ObjC.Block(args[4]);
                        completionHandler(1, credential);
                    }
                });
            }

            console.log("[+] SSL pinning bypass complete");
        }
        """

        return self.execute_script(session, script)

    def bypass_anti_debugging(self, session: InstrumentationSession) -> bool:
        """
        Bypass anti-debugging and anti-analysis checks.

        Hooks debugger detection APIs and forces them to report no debugger.

        Args:
            session: Active instrumentation session

        Returns:
            True if bypass applied successfully
        """
        script = """
        console.log("[*] Bypassing anti-debugging checks...");

        // Android Anti-Debug Bypass
        if (Java.available) {
            Java.perform(function() {
                // Hook Debug.isDebuggerConnected()
                try {
                    var Debug = Java.use('android.os.Debug');
                    Debug.isDebuggerConnected.implementation = function() {
                        console.log("[*] isDebuggerConnected() bypassed");
                        return false;
                    };
                } catch(e) {}
            });
        }

        // Native Anti-Debug Bypass
        // Hook ptrace to prevent anti-debug
        var ptrace_ptr = Module.findExportByName(null, 'ptrace');
        if (ptrace_ptr) {
            Interceptor.attach(ptrace_ptr, {
                onEnter: function(args) {
                    var request = args[0].toInt32();
                    // PTRACE_TRACEME = 0
                    if (request === 0) {
                        console.log("[*] ptrace(PTRACE_TRACEME) blocked");
                        args[0] = ptr(-1);
                    }
                }
            });
        }

        // Windows Anti-Debug Bypass
        var isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        if (isDebuggerPresent) {
            Interceptor.attach(isDebuggerPresent, {
                onLeave: function(retval) {
                    retval.replace(0);
                    console.log("[*] IsDebuggerPresent() bypassed");
                }
            });
        }

        var checkRemoteDebuggerPresent = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
        if (checkRemoteDebuggerPresent) {
            Interceptor.attach(checkRemoteDebuggerPresent, {
                onLeave: function(retval) {
                    retval.replace(0);
                    console.log("[*] CheckRemoteDebuggerPresent() bypassed");
                }
            });
        }

        console.log("[+] Anti-debugging bypass complete");
        """

        return self.execute_script(session, script)

    def dump_crypto_keys(
        self, session: InstrumentationSession, algorithm: str = "AES"
    ) -> List[Dict[str, Any]]:
        """
        Dump cryptographic keys and plaintext data from memory.

        Hooks crypto functions to extract keys and data before encryption.
        Based on Modern Hacker's Playbook: Offensive Use Case 2

        Args:
            session: Active instrumentation session
            algorithm: Crypto algorithm to target (AES, RSA, DES, etc.)

        Returns:
            List of extracted crypto data
        """
        extracted_data = []

        def message_handler(message, data):
            if message["type"] == "send":
                payload = message["payload"]
                if "crypto_data" in payload:
                    extracted_data.append(payload["crypto_data"])
                    self.logger.info(f"[Crypto] Extracted: {payload['crypto_data']['operation']}")

        script = f"""
        console.log("[*] Hooking {algorithm} crypto functions...");
        var cryptoData = [];

        if (Java.available) {{
            Java.perform(function() {{
                // Hook javax.crypto.Cipher
                try {{
                    var Cipher = Java.use('javax.crypto.Cipher');

                    // Hook doFinal to dump plaintext and key
                    Cipher.doFinal.overload('[B').implementation = function(input) {{
                        var operation = this.getOpMode();
                        var algorithm = this.getAlgorithm();

                        // Get the key
                        var keyBytes = null;
                        try {{
                            var key = Java.cast(this.spi.value.engineGetKey(), Java.use('javax.crypto.SecretKey'));
                            keyBytes = key.getEncoded();
                        }} catch(e) {{}}

                        var data = {{
                            crypto_data: {{
                                operation: operation === 1 ? "ENCRYPT" : "DECRYPT",
                                algorithm: algorithm.toString(),
                                data: Array.from(input).map(b => (b & 0xFF).toString(16).padStart(2, '0')).join(''),
                                key: keyBytes ? Array.from(keyBytes).map(b => (b & 0xFF).toString(16).padStart(2, '0')).join('') : null,
                                timestamp: Date.now()
                            }}
                        }};

                        send(data);
                        console.log("[*] Intercepted " + algorithm + " " + data.crypto_data.operation);

                        return this.doFinal.overload('[B').call(this, input);
                    }};
                }} catch(e) {{
                    console.log("[-] Cipher hook failed: " + e);
                }}
            }});
        }}

        // Native crypto hooks
        var cryptoFunctions = [
            'AES_encrypt', 'AES_decrypt',
            'RSA_public_encrypt', 'RSA_private_decrypt',
            'EVP_EncryptInit', 'EVP_DecryptInit'
        ];

        cryptoFunctions.forEach(function(funcName) {{
            var funcPtr = Module.findExportByName(null, funcName);
            if (funcPtr) {{
                Interceptor.attach(funcPtr, {{
                    onEnter: function(args) {{
                        console.log("[*] Native crypto: " + funcName);
                        // Can dump args here for more detail
                    }}
                }});
            }}
        }});

        console.log("[+] Crypto hooks installed");
        """

        self.execute_script(session, script, message_handler)
        return extracted_data

    def trace_api_calls(
        self, session: InstrumentationSession, pattern: Optional[str] = None
    ) -> List[HookResult]:
        """
        Trace all API calls, optionally filtered by pattern.

        Args:
            session: Active instrumentation session
            pattern: Regex pattern to filter function names

        Returns:
            List of traced API calls
        """
        traced_calls = []

        def message_handler(message, data):
            if message["type"] == "send":
                payload = message["payload"]
                if "api_call" in payload:
                    call_data = payload["api_call"]
                    traced_calls.append(
                        HookResult(
                            function_name=call_data["name"],
                            args=call_data.get("args", []),
                            return_value=call_data.get("return"),
                            timestamp=call_data.get("timestamp", 0),
                            backtrace=call_data.get("backtrace"),
                        )
                    )

        filter_pattern = pattern or ".*"

        script = f"""
        console.log("[*] Tracing API calls (pattern: {filter_pattern})...");

        var pattern = new RegExp("{filter_pattern}", "i");

        // Enumerate all modules and exports
        Process.enumerateModules().forEach(function(module) {{
            module.enumerateExports().forEach(function(exp) {{
                if (pattern.test(exp.name)) {{
                    try {{
                        Interceptor.attach(exp.address, {{
                            onEnter: function(args) {{
                                this.startTime = Date.now();
                                this.args = [];
                                for (var i = 0; i < 4; i++) {{
                                    try {{
                                        this.args.push(args[i].toString());
                                    }} catch(e) {{
                                        this.args.push("???");
                                    }}
                                }}
                            }},
                            onLeave: function(retval) {{
                                var call = {{
                                    api_call: {{
                                        name: exp.name,
                                        args: this.args,
                                        return: retval.toString(),
                                        timestamp: this.startTime,
                                        backtrace: Thread.backtrace(this.context).map(DebugSymbol.fromAddress).map(s => s.toString())
                                    }}
                                }};
                                send(call);
                            }}
                        }});
                    }} catch(e) {{}}
                }}
            }});
        }});

        console.log("[+] API tracing active");
        """

        self.execute_script(session, script, message_handler)
        return traced_calls

    def inject_code(
        self, session: InstrumentationSession, code: str, language: str = "javascript"
    ) -> bool:
        """
        Inject and execute custom code in the target process.

        Args:
            session: Active instrumentation session
            code: Code to inject
            language: Language (javascript, native)

        Returns:
            True if injection successful
        """
        if language == "javascript":
            return self.execute_script(session, code)
        elif language == "native":
            # For native code injection, we'd use Frida's Memory API
            # This is a simplified example
            wrapper_script = """
            var nativeCode = Memory.alloc(Process.pageSize);
            Memory.protect(nativeCode, Process.pageSize, 'rwx');
            // Write machine code here
            var nativeFunc = new NativeFunction(nativeCode, 'void', []);
            nativeFunc();
            """
            return self.execute_script(session, wrapper_script)
        else:
            self.logger.error(f"Unsupported language: {language}")
            return False

    def detach(self, session: InstrumentationSession):
        """Detach from instrumentation session"""
        try:
            if session.script:
                session.script.unload()
            session.session.detach()
            self.logger.info("Detached from session")
        except Exception as e:
            self.logger.error(f"Error detaching: {e}")

    def detach_all(self):
        """Detach from all active sessions"""
        for session_id, session in list(self.sessions.items()):
            self.detach(session)
            del self.sessions[session_id]


# Convenience function for quick instrumentation
def quick_bypass(process_name: str, bypass_type: str = "all") -> bool:
    """
    Quick bypass of common security controls.

    Args:
        process_name: Name of process to target
        bypass_type: Type of bypass (root, ssl, debug, all)

    Returns:
        True if successful
    """
    engine = DynamicInstrumentationEngine()
    target = InstrumentationTarget(process_name=process_name)
    session = engine.attach(target)

    if not session:
        return False

    success = True
    if bypass_type in ["root", "all"]:
        success &= engine.bypass_root_detection(session)
    if bypass_type in ["ssl", "all"]:
        success &= engine.bypass_ssl_pinning(session)
    if bypass_type in ["debug", "all"]:
        success &= engine.bypass_anti_debugging(session)

    return success
