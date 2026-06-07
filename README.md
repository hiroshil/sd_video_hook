# School Days Video Display Fix - Technical Report

## Problem
School Days (visual novel game) video does not display during playback on newer GPUs.
The game renders video to an offscreen render target but never draws it to the screen
via DrawPrimitiveUP due to a GPU capability check that fails on modern hardware.

## Root Cause Analysis

### Game Rendering Pipeline
1. **FILMEngine.gem** decodes video frames and writes them to a 640x348 render target surface
2. FILMEngine sets up texture stages (SetTextureStageState) and render states (SetRenderState)
3. A conditional check (`vtable[0x58]`) determines whether to proceed with DrawPrimitiveUP
4. On newer GPUs, this check returns 0 (fail), causing the game to skip DrawPrimitiveUP
5. Video surface is populated with video data but never drawn to screen

### Key Findings from Reverse Engineering
- **DX9GraphicBase.gem**: Manages render targets (SetRT), EndScene, Present
- **FILMEngine.gem**: Sets up texture/render state for video but relies on caller for DrawPrimitiveUP
- **SD.exe**: Contains DrawPrimitiveUP calls but guarded by conditional check at offset 0x40e183
- Render target switching pattern during video: video_surface(640x348) -> back_buffer(640x480) -> ui_surface(1024x64) -> back_buffer (repeating)
- SetRenderState(state=0xd1 / D3DRS_LIGHTING) is called by FILMEngine during video setup

## Solution: DLL Hook (sd_video_hook.dll)

### Architecture
- Rust cdylib DLL injected via IAT patching into SD_with_dll.exe
- Uses **retour-rs** (GenericDetour) for function prologue hooking
- Hooks D3D9 device methods via retour inline hooks

### Hooked Functions
| Function | Vtable Slot | Purpose |
|---|---|---|
| EndScene | 42 (0xa8) | Reset per-frame counter |
| SetRenderTarget | 37 (0x94) | Detect video render target (640x348) |
| SetRenderState | 57 (0xe4) | Trigger DrawPrimitiveUP on video setup |

### Key Technique: Frame Counter + SetRenderState Trigger

1. **SetRenderTarget hook**: Detects when game sets a 640x348 render target (video surface)
   - Stores the video RT address in `LAST_VIDEO_RT`

2. **EndScene hook**: Resets `RS_DRAW_COUNT` to 0 each frame
   - Ensures the trigger only fires once per frame

3. **SetRenderState hook**: When `state == 0xd1` (D3DRS_LIGHTING) during video playback:
   - Checks `RS_DRAW_COUNT == 0` (first call this frame = video setup)
   - Calls `DrawPrimitiveUP` with fullscreen quad vertices
   - Increments counter so subsequent calls (UI/hover) are ignored

### Vertex Data (Fullscreen Quad)
```
D3DFVF_XYZRHW | D3DFVF_TEX1 (stride = 24 bytes)
D3DPT_TRIANGLESTRIP, 2 primitives (4 vertices)

Vertices positioned at y=66 to y=414 (centered in 640x480 window)
UV coordinates: (0,0) to (1,1) mapping full video texture
```

### D3D9 Hook Chain
1. Hook `Direct3DCreate9` / `Direct3DCreate9Ex` via retour
2. Copy IDirect3D9 vtable, hook `CreateDevice` slot
3. In CreateDevice detour, hook device methods via retour

## Build Instructions
```bash
# Requires nightly Rust (i686-pc-windows-msvc target)
cargo build --release --target i686-pc-windows-msvc
# Output: target/i686-pc-windows-msvc/release/sd_video_hook.dll
```

## File Structure
```
sd_video_hook/
├── src/lib.rs          # Main hook source
├── Cargo.toml          # Dependencies (retour-rs, once_cell, windows)
├── rust-toolchain.toml # nightly toolchain
└── vendor/retour/      # Patched retour-rs (i686 win64 ABI fix)
```

## Version History
- v0.1-v0.8: Various approaches (StretchRect in EndScene/Present/SetRT, vtable patching, etc.)
  - StretchRect approaches either crashed or covered UI
  - Vtable patching of device hooks didn't intercept calls
  - Texture creation in hook context caused crashes
- v0.9: Stable StretchRect but covered UI
- **Final**: SetRenderState trigger with frame counter - video displays correctly with UI visible

## Key Insight
The game's FILMEngine sets up all the render states and textures correctly for video rendering
but never calls DrawPrimitiveUP (guarded by a GPU check that fails on modern hardware).
By hooking SetRenderState and injecting DrawPrimitiveUP at the exact moment the game sets
up video rendering (first D3DRS_LIGHTING call per frame), we draw the video quad using
the game's own texture and render state configuration. The frame counter ensures this
only triggers for video setup, not for UI or hover rendering which also use the same
render state.

## Credits

This project was developed with assistance from **Qwen3.7-Max**, Alibaba Cloud Qwen’s long-context reasoning model with a **1M-token context window**.

Special thanks to the Qwen team for making advanced long-context AI capabilities available to developers.
