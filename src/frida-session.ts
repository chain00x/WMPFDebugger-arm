import type { Device, Session, Script } from 'frida';

export async function deadline<T>(operation: Promise<T>, ms: number, label: string): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
        return await Promise.race([operation, new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
        })]);
    } finally { if (timer) clearTimeout(timer); }
}

export type Attached = { session: Session; script: Script; pid: number };
export async function detachChecked(handle: Partial<Attached>, ms = 1500) {
    // Try both operations, even if unload hangs. Never leave a polling loop
    // repeatedly attaching to a failed target.
    try { if (handle.script) await deadline(handle.script.unload(), ms, 'script.unload'); } catch {}
    try { if (handle.session) await deadline(handle.session.detach(), ms, 'session.detach'); } catch {}
}

export async function attachChecked(device: Device, pid: number, source: string, options: {
    timeoutMs?: number; requireReady?: boolean; log?: (message: string) => void;
    onMessage?: (message: any) => boolean;
} = {}): Promise<Attached> {
    const ms = options.timeoutMs || 5000;
    const handle: Partial<Attached> = { pid };
    let abandoned = false;
    const attach = device.attach(pid).then(async session => {
        if (abandoned) { await detachChecked({ session }); throw new Error('Late attach was detached'); }
        handle.session = session; return session;
    });
    try {
        handle.session = await deadline(attach, ms, 'attach');
        handle.script = await deadline(handle.session.createScript(source), ms, 'createScript');
        let readyResolve: () => void = () => {};
        const ready = new Promise<void>(resolve => { readyResolve = resolve; });
        let failure: string | undefined;
        handle.script.message.connect(message => {
            if (message.type === 'send' && message.payload?.type === 'wmpf-ready') readyResolve();
            if (message.type === 'error') failure = message.stack || message.description;
            // Consumed native-CDP payloads must never be dumped into log files.
            if (!options.onMessage?.(message)) options.log?.(JSON.stringify(message));
        });
        await deadline(handle.script.load(), ms, 'script.load');
        if (failure) throw new Error(failure);
        if (options.requireReady) await deadline(ready, ms, 'native-hook readiness');
        if (failure) throw new Error(failure);
        return handle as Attached;
    } catch (e) {
        abandoned = true;
        await detachChecked(handle, Math.min(ms, 1500));
        throw e;
    }
}
