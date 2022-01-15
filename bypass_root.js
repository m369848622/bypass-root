
var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk", "riru"];
var isDebugger = true;
var isStronger = false;
var isStrongerPlus = false;

function bypass_all() {
    bypass_root();
    bypass_open();
    // bypass_fgets();
    // bypass_kill();
    // bypass_fork();
    bypass_sslpinning();
    setTimeout(run,1000);
}

function find_all() {
    find_strstr();
    find_strcmp();
}

function run() {//hook js
    console.log('start hook');
    //response
    var SmNetworkUtil = Java.use("com.wsgw.intercept_sm.SmNetworkUtil");
    SmNetworkUtil.sm4De.implementation = function (str, str2) {
        var res = SmNetworkUtil.sm4De.call(this, str, str2);
        console.log('encryptData====================================================================================================');
        console.log('str->' + str);
        console.log('str2->' + str2);
        console.log('sm4De->' + res);
        console.log('encryptData====================================================================================================');
        return res;
    };
    SmNetworkUtil.sm2De.implementation = function (str, str2) {
        var res = SmNetworkUtil.sm2De.call(this, str, str2);
        console.log('respKey====================================================================================================');
        console.log('str->'+str);
        console.log('str2->'+str2);
        console.log( 'sm2De->'+res);
        console.log('respKey====================================================================================================');
        return res;
    };


    // header
    var TigerTallyAPI = Java.use("com.aliyun.TigerTally.TigerTallyAPI");
    TigerTallyAPI._genericNt3.implementation = function (str, str2) {
        var res = TigerTallyAPI._genericNt3.call(this, str, str2);
        console.log('====================================================================================================');
        console.log('str->'+str);
        console.log('str2->'+str2);
        console.log('_genericNt3->'+res);
        console.log('====================================================================================================');
        return res;
    };


    // request
    var SmEncryptUtil = Java.use("com.wsgw.intercept_sm.SmNetworkUtil");
    SmEncryptUtil.sm2En.implementation = function (str, str2) {
        var res = SmEncryptUtil.sm2En.call(this, str, str2);
        console.log('skey====================================================================================================');
        console.log('str->'+str);
        console.log('str2->'+str2);
        console.log('sm2En->'+res);
        console.log('skey====================================================================================================');
        return res;
    };
    SmNetworkUtil.sm4En.implementation = function (str, str2) {
        var res = SmNetworkUtil.sm4En.call(this, str, str2);
        console.log('data====================================================================================================');
        console.log('str->'+str);
        console.log('str2->'+str2);
        console.log( 'sm4En->'+res);
        console.log('data====================================================================================================');
        return res;
    };
    SmNetworkUtil.sm3Sign.implementation = function (str ) {
        var res = SmNetworkUtil.sm3Sign.call(this, str);
        console.log('sign====================================================================================================');
        console.log('str->'+str);
        console.log( 'sm3Sign->'+res);
        console.log('sign====================================================================================================');
        return res;
    };

    var Config = Java.use('com.sgcc.wsgw.publiclibrary.Config');
    Config.isDebug = true;

}


function bypass_root() {
    /* 
    https://codeshare.frida.re/@dzonerzy/fridantiroot/
    Original author: Daniele Linguaglossa
    28/07/2021 -    Edited by Simone Quatrini
                Code amended to correctly run on the latest frida version
                Added controls to exclude Magisk Manager
*/
    Java.perform(function () {
        var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
            "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
        ];


        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1"
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        var Runtime = Java.use('java.lang.Runtime');

        var NativeFile = Java.use('java.io.File');

        var String = Java.use('java.lang.String');

        var SystemProperties = Java.use('android.os.SystemProperties');

        var BufferedReader = Java.use('java.io.BufferedReader');

        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

        var StringBuffer = Java.use('java.lang.StringBuffer');

        var loaded_classes = Java.enumerateLoadedClassesSync();

        sendlog("Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        sendlog("ProcessManager loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

        if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
            try {
                useProcessManager = true;
                var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
                sendlog("ProcessManager Hook failed: " + err);
            }
        } else {
            sendlog("ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
            try {
                useKeyInfo = true;
                var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
                sendlog("KeyInfo Hook failed: " + err);
            }
        } else {
            sendlog("KeyInfo hook not loaded");
        }

        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
            var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
            if (shouldFakePackage) {
                sendlog("Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
        };

        NativeFile.exists.implementation = function () {
            var name = NativeFile.getName.call(this);
            var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
            if (shouldFakeReturn) {
                sendlog("Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
        };

        var exec = Runtime.exec.overload('[Ljava.lang.String;');
        var exec1 = Runtime.exec.overload('java.lang.String');
        var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
        var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
        var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
        var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

        exec5.implementation = function (cmd, env, dir) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                sendlog("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                sendlog("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec5.call(this, cmd, env, dir);
        };

        exec4.implementation = function (cmdarr, env, file) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    sendlog("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    sendlog("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec4.call(this, cmdarr, env, file);
        };

        exec3.implementation = function (cmdarr, envp) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    sendlog("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    sendlog("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec3.call(this, cmdarr, envp);
        };

        exec2.implementation = function (cmd, env) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                sendlog("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                sendlog("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec2.call(this, cmd, env);
        };

        exec.implementation = function (cmd) {
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                    var fakeCmd = "grep";
                    sendlog("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    sendlog("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
            }

            return exec.call(this, cmd);
        };

        exec1.implementation = function (cmd) {
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                var fakeCmd = "grep";
                sendlog("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                sendlog("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec1.call(this, cmd);
        };

        String.contains.implementation = function (name) {
            if (name == "test-keys") {
                sendlog("Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload('java.lang.String');

        get.implementation = function (name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                sendlog("Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };


        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function (args) {
                var cmd = Memory.readCString(args[0]);
                sendlog("SYSTEM CMD: " + cmd);
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                    sendlog("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    sendlog("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                }
            },
            onLeave: function (retval) {

            }
        });

        /*
    
        TO IMPLEMENT:
    
        Exec Family
    
        int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
        int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
        int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execv(const char *path, char *const argv[]);
        int execve(const char *path, char *const argv[], char *const envp[]);
        int execvp(const char *file, char *const argv[]);
        int execvpe(const char *file, char *const argv[], char *const envp[]);
    
        */


        BufferedReader.readLine.overload('boolean').implementation = function () {
            var text = this.readLine.overload('boolean').call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                if (shouldFakeRead) {
                    sendlog("Bypass build.prop file read");
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }
            }
            return text;
        };

        var executeCommand = ProcessBuilder.command.overload('java.util.List');

        ProcessBuilder.start.implementation = function () {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                sendlog("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                sendlog("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
            var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

            ProcManExec.implementation = function (cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        sendlog("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        sendlog("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function (cmd, env, directory, stdin, stdout, stderr, redirect) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        sendlog("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        sendlog("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function () {
                sendlog("Bypass isInsideSecureHardware");
                return true;
            }
        }

    });
}

function bypass_open(){
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function (args) {
            var pathReal = Memory.readCString(args[0]);
            var path;
            sendlog('path->' + pathReal);
            if (isStrongerPlus && pathReal.indexOf('proc/') > -1) {//if you can't pass anti can try this code
                path = pathReal.replaceAll(/\/(\d*|self)\//g, "/1/");
                sendlog("Bypass native fopen->proc->" + pathReal + "->" + path);
                Memory.writeUtf8String(args[0], path);
                // args[0] = Memory.allocUtf8String(path);
            }
            path = pathReal.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn || (isStronger && pathReal.indexOf('proc') == -1)) {//add some white string
                sendlog("Bypass native fopen->" + pathReal);
                Memory.writeUtf8String(args[0], "/notexists");
                // args[0] = Memory.allocUtf8String("/notexists");
            }
        },
        onLeave: function (retval) {
        }
    });
}

function bypass_kill() {
    Java.perform(function () {
        Interceptor.replace(new NativeFunction(Module.findExportByName(null, "kill"), 'void', ['int', 'int']), new NativeCallback(function (pid, SIGKILL) {
            console.log("Bypass native kill")
            return 0
        }, 'int', ['int', 'int']))
    })
}


function bypass_fgets() {
    var fgetsPtr = Module.findExportByName("libc.so", "fgets");
    var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
    Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
        var retval = fgets(buffer, size, fp);
        var bufstr = buffer.readCString();
        if (isStrongerPlus) {
            for (let index = 0; index < RootBinaries.length; index++) {
                const element = RootBinaries[index];
                if (bufstr.indexOf(element) > -1) {
                    sendlog('Bypass bufstr->' + bufstr);//如果这句数据了 很有可能检测到了其他地方 还得改改代码
                    Memory.writeUtf8String(buffer, "");
                }
            }
        }
        if (bufstr.indexOf("TracerPid:") > -1) {
            sendlog('Bypass TracerPid->' + bufstr);
            Memory.writeUtf8String(buffer, "TracerPid:\t0");
        }
        return retval;
    }, 'pointer', ['pointer', 'int', 'pointer']))
}

//from https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
function bypass_sslpinning() {
    Java.perform(function () {
        console.log("");
        console.log("[.] Cert Pinning Bypass/Re-Pinning");

        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedInputStream = Java.use("java.io.BufferedInputStream");
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        var KeyStore = Java.use("java.security.KeyStore");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        // Load CAs from an InputStream
        console.log("[+] Loading our CA...")
        var cf = CertificateFactory.getInstance("X.509");

        try {
            var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");//add your crt!!!!!!!!!!!!
        }
        catch (err) {
            console.log("[o] " + err);
        }

        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        var ca = cf.generateCertificate(bufferedInputStream);
        bufferedInputStream.close();

        var certInfo = Java.cast(ca, X509Certificate);
        console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

        // Create a KeyStore containing our trusted CAs
        console.log("[+] Creating a KeyStore for our CA...");
        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        // Create a TrustManager that trusts the CAs in our KeyStore
        console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
        var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);
        console.log("[+] Our TrustManager is ready...");

        console.log("[+] Hijacking SSLContext methods now...")
        console.log("[-] Waiting for the app to invoke SSLContext.init()...")

        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function (a, b, c) {
            console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
            console.log("[+] SSLContext initialized with our custom TrustManager!");
        }
    });
}

function bypass_fork() {
    Java.perform(function () {
        // Interceptor.attach(Module.findExportByName("libc.so", "fork"), {
        //     onEnter: function (args) {
        //         console.log('fork_addr', 'entry');
        //     },
        //     onLeave: function (retval) {
        //     }
        // });
        Interceptor.replace(Module.findExportByName("libc.so", "fork"), new NativeCallback(function () {
            console.log('fork_addr', 'entry');
            return -1;
        }, 'int', []));
    })
}


/**
 * equals string such as test-keys...
 */
function find_strstr() {
    Java.perform(function () {
        Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
            onEnter: function (args) {
                var str0 = Memory.readCString(args[0]);
                var str1 = Memory.readCString(args[1]);
                sendlog("strstr->" + str0 + "--" + str1);
            },
            onLeave: function (retval) {
            }
        });
    })
}

/**
 * equals string such as test-keys...
 */
function find_strcmp() {
    Java.perform(function () {
        Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), {
            onEnter: function (args) {
                // this.found = false;
                var str0 = Memory.readCString(args[0]);
                var str1 = Memory.readCString(args[1]);
                sendlog("strcmp->" + str0 + "--" + str1);
                if (str1.indexOf('interceptor') != -1) {
                    this.found = true;
                }
            },
            onLeave: function (retval) {
                if(this.found){
                    retval.replace(ptr("0xfffffffe"));
                    sendlog("Bypass strcmp");
                }
            }
        });
    })
}

function sendlog(str) {
    if (isDebugger) {
        console.log(str);
    }
}

function sendBacktrace(context) {
    console.log("open" + ' called from:\n' +
    Thread.backtrace(context, Backtracer.FUZZY)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
}

setImmediate(bypass_all, 0);