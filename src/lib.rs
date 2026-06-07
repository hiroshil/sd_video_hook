#![allow(non_snake_case, non_camel_case_types, static_mut_refs, dead_code, unused_variables)]

use once_cell::sync::Lazy;
use retour::GenericDetour;
use std::ffi::{c_void, CString};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use windows::core::PCSTR;
use windows::Win32::Foundation::{BOOL, HINSTANCE};
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringA;
use windows::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, GetModuleHandleA, LoadLibraryA};
use windows::Win32::System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::Threading::{CreateThread, Sleep, THREAD_CREATION_FLAGS};

type FnD3D9Create = unsafe extern "system" fn(u32) -> *mut c_void;
type FnD3D9CreateEx = unsafe extern "system" fn(u32, *mut *mut c_void) -> i32;
type FnCreateDevice = unsafe extern "system" fn(
    *mut c_void, u32, u32, *mut c_void, u32, *mut c_void, *mut *mut c_void,
) -> i32;
type FnEndScene = unsafe extern "system" fn(*mut c_void) -> i32;
type FnSetRenderTarget = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
type FnSetRenderState = unsafe extern "system" fn(*mut c_void, u32, u32) -> i32;
type FnDrawPrimitiveUP = unsafe extern "system" fn(*mut c_void, u32, u32, *const c_void, u32) -> i32;
type FnSetTexture = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
type FnStretchRect = unsafe extern "system" fn(
    *mut c_void, *mut c_void, *const c_void, *mut c_void, *const c_void, u32,
) -> i32;

static mut HOOK_D3D9_CREATE: Option<GenericDetour<FnD3D9Create>> = None;
static mut HOOK_D3D9_CREATE_EX: Option<GenericDetour<FnD3D9CreateEx>> = None;
static mut HOOK_END_SCENE: Option<GenericDetour<FnEndScene>> = None;
static mut HOOK_SET_RT: Option<GenericDetour<FnSetRenderTarget>> = None;
static mut HOOK_SET_RS: Option<GenericDetour<FnSetRenderState>> = None;

// Frame counter: reset in EndScene, only draw on first SetRenderState(0xd1) per frame
static RS_DRAW_COUNT: AtomicUsize = AtomicUsize::new(0);

static BOOTSTRAP_STARTED: AtomicBool = AtomicBool::new(false);
static DEVICE_CAPTURED: AtomicBool = AtomicBool::new(false);
static mut REAL_D3D9_CREATE: *const c_void = ptr::null();
static mut ORIG_CREATE_DEVICE: Option<FnCreateDevice> = None;
static LAST_VIDEO_RT: AtomicUsize = AtomicUsize::new(0);
static LAST_CURRENT_RT: AtomicUsize = AtomicUsize::new(0);
static FORCED_FRAMES: AtomicUsize = AtomicUsize::new(0);

struct Logger { file: Option<File> }
impl Logger {
    fn new() -> Self {
        let path = std::env::current_exe().ok()
            .and_then(|p| p.parent().map(|d| d.join("hook_rebuilt.log")))
            .unwrap_or_else(|| PathBuf::from("hook_rebuilt.log"));
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path).ok();
        Self { file }
    }
    fn line(&mut self, msg: &str) {
        let full = format!("{}\r\n", msg);
        if let Some(f) = self.file.as_mut() { let _ = f.write_all(full.as_bytes()); let _ = f.flush(); }
        unsafe { if let Ok(c) = CString::new(full) { OutputDebugStringA(PCSTR(c.as_ptr() as *const u8)); } }
    }
}
static LOGGER: Lazy<Mutex<Logger>> = Lazy::new(|| Mutex::new(Logger::new()));
fn log(msg: impl AsRef<str>) { if let Ok(mut l) = LOGGER.lock() { l.line(msg.as_ref()); } }

// ── D3D9 create hooks ──

unsafe extern "system" fn hook_d3d9_create(sdk: u32) -> *mut c_void {
    let orig = HOOK_D3D9_CREATE.as_ref().expect("D3D9 hook");
    let d3d_ptr = orig.call(sdk);
    log(format!("[D3D9] call, result={:p}", d3d_ptr));
    if d3d_ptr.is_null() || DEVICE_CAPTURED.load(Ordering::Acquire) { return d3d_ptr; }
    let vtable = *(d3d_ptr as *const *const *const c_void);
    let new_vtable = match alloc_exec(32 * std::mem::size_of::<*const c_void>()) {
        Some(p) => p as *mut *const c_void, None => return d3d_ptr,
    };
    std::ptr::copy_nonoverlapping(vtable, new_vtable, 32);
    ORIG_CREATE_DEVICE = Some(std::mem::transmute(*vtable.add(16)));
    *new_vtable.add(16) = detour_create_device as *const c_void;
    let obj_vt = d3d_ptr as *mut *const c_void;
    let mut old = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(obj_vt as *mut c_void, 4, PAGE_EXECUTE_READWRITE, &mut old);
    std::ptr::write(obj_vt, new_vtable as *const c_void);
    let _ = VirtualProtect(obj_vt as *mut c_void, 4, old, &mut old);
    DEVICE_CAPTURED.store(true, Ordering::Release);
    log("[VT-COPY] IDirect3D9 vtable copied");
    d3d_ptr
}

unsafe extern "system" fn hook_d3d9_create_ex(sdk: u32, out: *mut *mut c_void) -> i32 {
    let orig = HOOK_D3D9_CREATE_EX.as_ref().expect("D3D9Ex hook");
    let hr = orig.call(sdk, out);
    if hr >= 0 && !out.is_null() && !(*out).is_null() && !DEVICE_CAPTURED.load(Ordering::Acquire) {
        let d3d_ptr = *out;
        let vtable = *(d3d_ptr as *const *const *const c_void);
        let new_vtable = match alloc_exec(32 * std::mem::size_of::<*const c_void>()) {
            Some(p) => p as *mut *const c_void, None => return hr,
        };
        std::ptr::copy_nonoverlapping(vtable, new_vtable, 32);
        ORIG_CREATE_DEVICE = Some(std::mem::transmute(*vtable.add(16)));
        *new_vtable.add(16) = detour_create_device as *const c_void;
        let obj_vt = d3d_ptr as *mut *const c_void;
        let mut old = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(obj_vt as *mut c_void, 4, PAGE_EXECUTE_READWRITE, &mut old);
        std::ptr::write(obj_vt, new_vtable as *const c_void);
        let _ = VirtualProtect(obj_vt as *mut c_void, 4, old, &mut old);
        DEVICE_CAPTURED.store(true, Ordering::Release);
    }
    hr
}

unsafe extern "system" fn detour_create_device(
    d3d9: *mut c_void, adapter: u32, device_type: u32, hwnd: *mut c_void,
    behavior: u32, pp: *mut c_void, out_device: *mut *mut c_void,
) -> i32 {
    let orig = ORIG_CREATE_DEVICE.expect("orig CreateDevice");
    let hr = orig(d3d9, adapter, device_type, hwnd, behavior, pp, out_device);
    log(format!("[CreateDevice] hr=0x{:x} out={:p}", hr,
        if out_device.is_null() { ptr::null() } else { *out_device }));
    if hr == 0 && !out_device.is_null() {
        let device = *out_device;
        if !device.is_null() { install_device_hooks(device); }
    }
    hr
}

unsafe fn install_device_hooks(device: *const c_void) {
    let vtable = *(device as *const *const *const c_void);
    let es: FnEndScene = std::mem::transmute(*vtable.add(42));
    let srt: FnSetRenderTarget = std::mem::transmute(*vtable.add(37));
    if let Ok(h) = GenericDetour::<FnEndScene>::new(es, detour_end_scene) {
        if h.enable().is_ok() { HOOK_END_SCENE = Some(h); log("[OK] EndScene hooked"); }
    }
    if let Ok(h) = GenericDetour::<FnSetRenderTarget>::new(srt, detour_set_render_target) {
        if h.enable().is_ok() { HOOK_SET_RT = Some(h); log("[OK] SetRT hooked"); }
    }
    // Hook SetRenderState (slot 57, offset 0xe4)
    let set_rs: FnSetRenderState = std::mem::transmute(*vtable.add(57));
    if let Ok(h) = GenericDetour::<FnSetRenderState>::new(set_rs, detour_set_rs) {
        if h.enable().is_ok() { HOOK_SET_RS = Some(h); log("[OK] SetRenderState hooked"); }
    }
    log(format!("[DEV] {:p} — hooks installed", device));
}

unsafe fn describe_rt(surface: *mut c_void) -> (u32, u32, u32) {
    if surface.is_null() { return (0, 0, 0); }
    let vtable = *(surface as *const *const *const c_void);
    type FnGetDesc = unsafe extern "system" fn(*mut c_void, *mut [u32; 8]) -> i32;
    let get_desc: FnGetDesc = std::mem::transmute(*vtable.add(12));
    let mut desc: [u32; 8] = [0; 8];
    if get_desc(surface, &mut desc) == 0 { (desc[6], desc[7], desc[0]) } else { (0, 0, 0) }
}

unsafe extern "system" fn detour_set_render_target(device: *mut c_void, index: u32, surface: *mut c_void) -> i32 {
    let orig = HOOK_SET_RT.as_ref().expect("SetRT hook");
    static SRT_COUNT: AtomicUsize = AtomicUsize::new(0);
    let n = SRT_COUNT.fetch_add(1, Ordering::AcqRel);
    let hr = orig.call(device, index, surface);
    if hr == 0 && index == 0 && !surface.is_null() {
        LAST_CURRENT_RT.store(surface as usize, Ordering::Release);
        let (w, h, fmt) = describe_rt(surface);
        let looks_video = (w == 640 && h == 348) || (w == 768 && h == 512)
            || fmt == 0x59565955 || fmt == 0x32595559;
        if n < 50 { log(format!("[SRT] #{}: {:p} {}x{} fmt=0x{:x} video={}", n, surface, w, h, fmt, looks_video)); }
        if looks_video {
            LAST_VIDEO_RT.store(surface as usize, Ordering::Release);
            log(format!("[SRT] video surface {:p}", surface));
        }
    }
    hr
}

// StretchRect BEFORE orig EndScene (video first, then game renders UI on top)
// SetRenderState detour: only DrawPrimitiveUP on first call per frame (video setup)
unsafe extern "system" fn detour_set_rs(device: *mut c_void, state: u32, value: u32) -> i32 {
    let orig = HOOK_SET_RS.as_ref().expect("SetRS hook");
    let hr = orig.call(device, state, value);

    let video_rt = LAST_VIDEO_RT.load(Ordering::Acquire);
    // Only trigger on first SetRenderState(0xd1) per frame during video
    if video_rt != 0 && state == 0xd1 {
        let count = RS_DRAW_COUNT.fetch_add(1, Ordering::AcqRel);
        if count == 0 {
            // First call this frame = video setup → force DrawPrimitiveUP
            let dev_vt = *(device as *const *const *const c_void);
            type FnDup = unsafe extern "system" fn(*mut c_void, u32, u32, *const c_void, u32) -> i32;
            let draw_up: FnDup = std::mem::transmute(*dev_vt.add(83));

            #[repr(C)]
            struct Vertex { x: f32, y: f32, z: f32, rhw: f32, u: f32, v: f32 }
            static VERTS: [Vertex; 4] = [
                Vertex { x: 0.0,   y: 66.0,  z: 0.0, rhw: 1.0, u: 0.0, v: 0.0 },
                Vertex { x: 640.0, y: 66.0,  z: 0.0, rhw: 1.0, u: 1.0, v: 0.0 },
                Vertex { x: 0.0,   y: 414.0, z: 0.0, rhw: 1.0, u: 0.0, v: 1.0 },
                Vertex { x: 640.0, y: 414.0, z: 0.0, rhw: 1.0, u: 1.0, v: 1.0 },
            ];

            let hr2 = draw_up(device, 5, 2, VERTS.as_ptr() as *const c_void, 24);
            static FORCE_COUNT: AtomicUsize = AtomicUsize::new(0);
            let c = FORCE_COUNT.fetch_add(1, Ordering::AcqRel);
            if c < 5 || c % 300 == 0 {
                log(format!("[FORCE-RS] #{} hr=0x{:x}", c, hr2));
            }
        }
    }
    hr
}

// EndScene: reset frame counter
unsafe extern "system" fn detour_end_scene(device: *mut c_void) -> i32 {
    let orig = HOOK_END_SCENE.as_ref().expect("EndScene hook");
    static ES_COUNT: AtomicUsize = AtomicUsize::new(0);
    let n = ES_COUNT.fetch_add(1, Ordering::AcqRel);

    // Reset frame counter so next frame's first SetRenderState(0xd1) triggers draw
    RS_DRAW_COUNT.store(0, Ordering::Release);

    let hr = orig.call(device);
    if n < 10 || n % 300 == 0 { log(format!("[ES] #{}", n)); }
    hr
}

unsafe fn alloc_exec(size: usize) -> Option<*mut u8> {
    let p = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if p.is_null() { None } else { Some(p as *mut u8) }
}

unsafe fn worker_thread_body() {
    log("=== sd_video_hook v16.0 (retour + StretchRect BEFORE EndScene + correct offsets) ===");
    if let Ok(h) = LoadLibraryA(PCSTR(b"d3d9.dll\0".as_ptr())) { log(format!("[PRELOAD] d3d9.dll @ {:p}", h.0)); }
    let d3d_mod = match GetModuleHandleA(PCSTR(b"d3d9.dll\0".as_ptr())) { Ok(m) => m, Err(e) => { log(format!("[ERR] {e}")); return; } };
    log(format!("[MOD] d3d9.dll @ {:p}", d3d_mod.0));
    if let Some(sym) = windows::Win32::System::LibraryLoader::GetProcAddress(d3d_mod, PCSTR(b"Direct3DCreate9\0".as_ptr())) {
        let addr = sym as *const c_void;
        if !addr.is_null() {
            REAL_D3D9_CREATE = addr;
            if let Ok(h) = GenericDetour::<FnD3D9Create>::new(std::mem::transmute(addr), hook_d3d9_create) {
                if h.enable().is_ok() { HOOK_D3D9_CREATE = Some(h); log("[OK] Direct3DCreate9 hooked"); }
            }
        }
    }
    if let Some(sym) = windows::Win32::System::LibraryLoader::GetProcAddress(d3d_mod, PCSTR(b"Direct3DCreate9Ex\0".as_ptr())) {
        let addr = sym as *const c_void;
        if !addr.is_null() {
            if let Ok(h) = GenericDetour::<FnD3D9CreateEx>::new(std::mem::transmute(addr), hook_d3d9_create_ex) {
                if h.enable().is_ok() { HOOK_D3D9_CREATE_EX = Some(h); log("[OK] Direct3DCreate9Ex hooked"); }
            }
        }
    }
    for tick in 0..120000u32 {
        if tick % 1200 == 0 {
            log(format!("[STATE] tick={} dev={} rt=0x{:x} forced={}",
                tick, DEVICE_CAPTURED.load(Ordering::Acquire),
                LAST_VIDEO_RT.load(Ordering::Acquire), FORCED_FRAMES.load(Ordering::Acquire)));
        }
        Sleep(1);
    }
}

unsafe extern "system" fn worker_thread(_: *mut c_void) -> u32 { worker_thread_body(); 0 }
unsafe fn bootstrap_once() {
    if BOOTSTRAP_STARTED.swap(true, Ordering::AcqRel) { return; }
    let _ = CreateThread(None, 0, Some(worker_thread), None, THREAD_CREATION_FLAGS(0), None);
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(hinst: HINSTANCE, reason: u32, _: *mut c_void) -> BOOL {
    if reason == 1 { let _ = DisableThreadLibraryCalls(hinst); bootstrap_once(); }
    BOOL(1)
}
