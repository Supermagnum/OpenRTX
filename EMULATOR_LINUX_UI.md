# Linux SDL emulator: menus and settings

The usual **desktop emulator** targets are **`openrtx_linux`** and **`openrtx_linux_smallscreen`**. They open an SDL window titled *OpenRTX* and run the **default** UI (`ui/default`), same family as many handheld radios.

Build and run (from a configured Meson build directory):

```bash
meson compile -C build openrtx_linux
./build/openrtx_linux
```

Use **`openrtx_linux_smallscreen`** if you want the smaller-screen layout. The **keyboard mappings below are the same**; they are implemented in `platform/targets/linux/emulator/sdl_engine.c`.

This document does **not** apply to the **Module17** UI (`openrtx_linux_mod17`), which uses different menus and inputs.

## Keyboard map (radio front panel)

| Key (SDL) | Role |
|-----------|------|
| Digit keys **0**–**9** | Keypad digits |
| **\*** (asterisk on main keyboard) | `KEY_STAR` |
| **#** (hash) | `KEY_HASH` |
| **Enter** | `KEY_ENTER` (confirm / open menu from main screen) |
| **Esc** | `KEY_ESC` (back / cancel) |
| **Arrow Up / Down** | Move highlight in menus; tune frequency on VFO (with channel limits) |
| **Arrow Left / Right** | Text edit / numeric inputs where supported |
| **Page Up** | Emulates **channel knob left** (`KNOB_LEFT`) |
| **Page Down** | Emulates **channel knob right** (`KNOB_RIGHT`) |
| **n** | `KEY_F1` (voice-prompt repeat / summary when voice prompts above *beep* level) |
| **m** | `KEY_MONI` (monitor function where implemented) |

**Push-to-talk:** hold **P** while the SDL window has focus (`platform/targets/linux/platform.c` uses `SDL_SCANCODE_P`). The emulator thread also accepts **`ptt`** on the stdin control interface (below).

## Changing menus

1. From **VFO** (`MAIN_VFO`) or **channel** (`MAIN_MEM`) screen, press **Enter** to open the **top menu** (`MENU_TOP`).
2. Use **Up** / **Down** (or **Page Up** / **Page Down** as knob) to move between entries: Banks, Channels, Contacts, Settings, Info, About (and GPS on GPS-enabled builds).
3. Press **Enter** to open the highlighted submenu.
4. Press **Esc** to go **back** one level (to the previous screen).

## Changing settings

1. Open the top menu (**Enter** from main).
2. Select **Settings** and press **Enter** (`MENU_SETTINGS`).
3. Move with **Up** / **Down** (or **Page Up** / **Page Down**), then **Enter** on a row to open that category (Display, Time and Date if RTC is enabled, GPS if enabled, Radio, M17 if enabled, FM, Accessibility, Reset to defaults).
4. Inside a category, the same keys apply: **Up** / **Down** to choose an item, **Enter** to edit or enter a sub-screen, **Esc** to return to **Settings** or the menu above.

Exact items depend on `hwconfig.h` for the Linux target (`CONFIG_GPS`, `CONFIG_RTC`, `CONFIG_M17`, brightness, etc.). The default Linux `hwconfig` includes **M17** but not **Horse**; **Horse** appears only on builds that define **`CONFIG_HORSE`** (for example MD-3x0 firmware), not in the stock Linux emulator profile.

## Optional: stdin “shell” (RSSI, channel, scripted keys)

When the build finds **GNU Readline** (for example `libreadline-dev` on Debian/Ubuntu), Meson enables **`CONFIG_READLINE`** and a thread may accept **text commands** on stdin (see `platform/targets/linux/emulator/emulator.c`): **`help`** lists commands such as **`rssi`**, **`vbat`**, **`mic`**, **`volume`**, **`channel`**, **`ptt`**, **`key`** (sequence of key names like `ENTER DOWN ENTER`), **`screenshot`**, **`quit`**.  
Use **`key`** / **`keycombo`** to drive the UI from scripts; names match the `KEY_*` identifiers (for example `ESC`, `ENTER`, `UP`, `F1`).

## Reference

- SDL key translation: `platform/targets/linux/emulator/sdl_engine.c` (`sdk_key_code_to_key`)
- Menu handling: `openrtx/src/ui/default/ui.c` (e.g. `MENU_TOP`, `MENU_SETTINGS`, `SETTINGS_*`)
- Menu labels and structure: `openrtx/include/ui/ui_default.h`
