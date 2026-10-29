// WeChat WebView F12调试 - 使用ObjC查找并调用调试类
const getMainModule = () => {
  return Process.findModuleByName('WeChatAppEx Framework')
}

const moduleBase = getMainModule().base;

if (moduleBase) {
    console.log("[+] Module base: " + moduleBase.toString());
    
    // Hook配置开关
    var configFunc = moduleBase.add(0x5088e00);
    Interceptor.attach(configFunc, {
        onLeave: function(retval) {
            var switchId = this.context.x2.toInt32();
            if (switchId === 6 || switchId === 7 || switchId === 12) {
                console.log("[+] Force enable switch " + switchId);
                retval.replace(1);
            }
        }
    });
    
    console.log("[+] Hook installed!");
} else {
    console.log("[-] Module not found!");
}

// 尝试查找调试相关类
if (ObjC.available) {
    console.log("[*] Searching for debug classes...");
    
    var debugClasses = [];
    var allClasses = ObjC.enumerateLoadedClasses();
    
    for (var i = 0; i < allClasses.length; i++) {
        var name = allClasses[i];
        if (name.indexOf("Debug") !== -1 || name.indexOf("DevTools") !== -1 || name.indexOf("Remote") !== -1) {
            debugClasses.push(name);
        }
    }
    
    console.log("[*] Found debug classes: " + debugClasses.join(", "));
    
    // 尝试查找包含调试UI方法的类
    setTimeout(function() {
        var uiClasses = [];
        for (var i = 0; i < allClasses.length; i++) {
            var name = allClasses[i];
            if (name.indexOf("Controller") !== -1 && (name.indexOf("Debug") !== -1 || name.indexOf("DevTool") !== -1)) {
                uiClasses.push(name);
            }
        }
        console.log("[*] UI Classes: " + uiClasses.join(", "));
    }, 3000);
}

console.log("[*] =======================================");
console.log("[*] 在微信中打开任意网页后，尝试查找调试入口...");
console.log("[*] =======================================");
