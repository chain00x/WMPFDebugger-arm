// macOS26: frida Module 枚举会装 dyld interposition 引发后续 dlopen 崩溃，
// 改用 _dyld_* 原生函数直接读镜像表；子进程可能未加载框架 → 空保护退出
const getMainModule = () => {
    try {
        const cnt = new NativeFunction(Module.getGlobalExportByName('_dyld_image_count'), 'ulong', [])
        const getName = new NativeFunction(Module.getGlobalExportByName('_dyld_get_image_name'), 'pointer', ['ulong'])
        const getHdr = new NativeFunction(Module.getGlobalExportByName('_dyld_get_image_header'), 'pointer', ['ulong'])
        const n = cnt()
        for (let i = 0; i < n; i++) {
            const namePtr = getName(i)
            if (namePtr.isNull()) continue
            const name = namePtr.readCString()
            if (name && name.indexOf('WeChatAppEx Framework') !== -1) return { base: getHdr(i) }
        }
    } catch (e) {}
    return null
}

const mainModule = getMainModule()
if (!mainModule) { console.log('[frida-4.1.0.240] framework not loaded yet, script exits (child ok)'); }
else {
const moduleBase = mainModule.base;


//搜索SendToClientFilter
Interceptor.attach(moduleBase.add(0x7D71940), {
    onEnter(args) {
        // console.log("[hook] sub_7D71940 onEnter");
    },
    onLeave(retval) {
        // console.log("[hook] sub_7D71940 onLeave, retval:", retval);
        if (retval && !retval.isNull()) {
            // Modify v8[2] to ensure it equals 6
            // v8[2] corresponds to offset 8 (since each element is 4 bytes)
            const v8_2_address = retval.add(8);
            // console.log("[hook] sub_7D71940 - Current v8[2] value:", v8_2_address.readU32());
            if (v8_2_address.readU32() == 6) {
                v8_2_address.writeU32(0x0);
            }
            // console.log("[hook] sub_7D71940 - Modified v8[2] to:", v8_2_address.readU32());
        }
    }
});

//搜索[perf] AppletIndexContainer::OnLoadStart，最后一个的函数，参考readme
Interceptor.attach(moduleBase.add(0x7D80A10), {
    onEnter(args) {
        // console.log("[inteceptor] sub_7D80A10 onEnter, first_param: ", args[0]);
        
        try {
            const result = args[0];
            const v4 = result.add(8).readPointer();
            
            if (v4 && !v4.isNull()) {
                const qword1 = v4.add(1336).readPointer();
                if (qword1 && !qword1.isNull()) {
                    const qword2 = qword1.add(16).readPointer();
                    if (qword2 && !qword2.isNull()) {
                        const targetAddress = qword2.add(488);
                        const currentValue = targetAddress.readInt();
                        // console.log("[inteceptor] sub_7D80A10 - Current value:", currentValue);
                        
                        // Only proceed if currentValue is in the allowed range
                        const allowedValues = [1005, 1007, 1008, 1027, 1035, 1053, 1074, 1145, 1256, 1260, 1302, 1308];
                        if (allowedValues.includes(currentValue)) {
                            // console.log("[inteceptor] sub_7D80A10 - Value in allowed range, setting to 1101");
                            targetAddress.writeInt(1101);
                            // console.log("[inteceptor] sub_7D80A10 - Value set to 1101 successfully");
                        } else {
                            // console.log("[inteceptor] sub_7D80A10 - Value not in allowed range, skipping modification");
                            return;
                        }
                    }
                }
            }
        } catch (error) {
            console.error("[inteceptor] sub_7D80A10 - Error during processing:", error);
        }
    },
    onLeave(retval) {
        // do nothing
    }
});



// 搜索[perf] AppletIndexContainer::OnLoadStart
Interceptor.attach(moduleBase.add(0x4EAF204), {
    onEnter(args) {
        // console.log("[inteceptor] sub_4EAF204 onEnter, first_param: ", args[0], "second_param: ", args[1]);
        
        // In ARM64 architecture, the second parameter is passed in X1 register
        // Based on IDA disassembly: MOV X20, X1 (0x4EAF21C)
        // We'll directly modify the X1 register to ensure it's always true
        this.context.x1 = (this.context.x1 & ~0xFF) | 0x1;
        // console.log("[inteceptor] Second parameter (X1) set to always true: ", this.context.x1);
    },
    onLeave(retval) {
        // do nothing
    }
});

//搜索WAPCAdapterAppIndex.js，第一个引用
Interceptor.attach(moduleBase.add(0x4F0555C), {
    onEnter(args) {
    },onLeave(retval) {
        retval.replace(0x0);
    }
});
}
